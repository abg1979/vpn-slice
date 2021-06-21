import os
import pathlib
import re
import subprocess
from ipaddress import ip_network, IPv4Network

from .dnspython import DNSPythonProvider
from .posix import HostsFileProvider, PosixProcessProvider
from .provider import RouteProvider, TunnelPrepProvider
from .util import get_executable
import logging


def win_exec(args, check=True):
    logger = logging.getLogger(__name__)
    process_args = list(map(str, args))
    logger.info('||||EXEC  ||||----> [%s]', format_command(process_args))
    completed_process = subprocess.run(process_args, universal_newlines=True, capture_output=True,
                                       encoding='utf8')
    for stdout_line in completed_process.stdout.splitlines():
        logger.debug("||||STDOUT||||----> [%s]", repr(stdout_line))
    for stderr_line in completed_process.stderr.splitlines():
        logger.debug("||||STDERR||||----> [%s]", repr(stderr_line))
    if check:
        completed_process.check_returncode()
    return completed_process.stdout


def format_command(args):
    return ' '.join(args)


def parse_pwsh_flat_table(lines):
    info_d = {}
    for line in lines:
        if ':' not in line:
            continue
        key, _, val = line.partition(':')
        info_d[key.strip()] = val.strip()
    return info_d


def parse_pwsh_table(lines):
    logger = logging.getLogger(__name__)
    info_d = []
    found_keys = False
    columns = []
    spaces_pattern = re.compile(r'(\s+)')
    separator_line_pattern = re.compile(r'[-\s]+')
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if separator_line_pattern.match(line):
            continue
        # first line contains keys
        # second line has separator ---
        # size of separator is same as size of key name
        if not found_keys:
            start = 0
            for match in re.finditer(spaces_pattern, line):
                column_name = line[start: match.start()]
                columns.append((column_name, start, match.end()))
                start = match.end()
            column_name = line[start:]
            columns.append((column_name, start, -1))
            found_keys = True
            continue
        record = {}
        for column in columns:
            if column[2] == -1:
                value = line[column[1]:]
            else:
                value = line[column[1]:column[2]]
            record[column[0]] = value.strip()
        logger.debug("Record = [%s]", record)
        info_d.append(record)
    return info_d


class Win32ProcessProvider(PosixProcessProvider):
    def __init__(self):
        super().__init__()
        self.ps = get_executable("powershell.exe")
        self.pwsh = get_executable("pwsh.exe")
        self.process_tree = None

    def get_process_tree(self, pid):
        logger = logging.getLogger(__name__)
        if self.process_tree is None:
            expression = ["@{Expression={$_.Id};Alignment='Left';Name='Id'}",
                          "@{Expression={$_.Parent.Id};Name='Parent';Alignment='Left'}", 'Path']
            command = ['Get-Process', '|', 'Format-Table', '-AutoSize', ",".join(expression)]
            info = win_exec([self.pwsh, '-Command', " ".join(command)])
            lines = iter(info.splitlines())
            info_d = parse_pwsh_table(lines)
            self.process_tree = info_d
        process_id = str(pid)
        p_tree = []
        while process_id:
            process_exists = False
            for process_info in self.process_tree:
                logger.debug("Checking [%s] with [%s]", process_info['Id'], process_id)
                if process_info['Id'] == process_id:
                    process_exists = True
                    p_tree.append(process_info)
                    process_id = process_info['Parent']
                    logger.debug("Found parent process id as [%s]", process_id)
                    break
            if not process_exists:
                # did not find the process, it may have exited
                logger.debug("Did not find [%s], it may have exited.", process_id)
                break
        return p_tree

    def pid2exe(self, pid):
        logger = logging.getLogger(__name__)
        process_tree = self.get_process_tree(pid)
        logger.debug("Found process info as [%s]", process_tree)
        if len(process_tree) > 0:
            return process_tree[0]['Path']
        return None

    # DONE
    def ppid_of(self, pid=None):
        if pid is None:
            return os.getppid()
        process_tree = self.get_process_tree(pid)
        if len(process_tree) > 0:
            return int(process_tree[0]['Parent'])
        return None


class WinHostsFileProvider(HostsFileProvider):
    # DONE
    def __init__(self):
        try:
            windir = pathlib.Path(os.environ["WINDIR"])
        except KeyError:
            raise OSError("Cannot read WINDIR environment variable")
        super().__init__(
            os.path.join(windir / "System32" / "drivers" / "etc" / "hosts")
        )

    # DONE
    def lock_hosts(self, handle):
        pass


class WinRouteProvider(RouteProvider):
    def __init__(self):
        self.ps = get_executable("powershell.exe")

    def _family_option(self, destination):
        return "IPv6" if destination.version == 6 else "IPv4"

    # TODO destination can be IP or IP with mask, convert that
    def add_route(self, destination, via=None, dev=None, src=None, mtu=None, **kwargs):
        logger = logging.getLogger(__name__)
        logger.debug("Args: [%s],[%s],[%s],[%s],[%s],[%s]", destination, via, dev, src, mtu, kwargs)
        args = ["-AddressFamily", self._family_option(destination)]
        args.extend(['-DestinationPrefix', ip_network(destination)])
        if mtu is not None:
            # not supported in windows
            pass  # https://serverfault.com/questions/878132
        if via is not None:
            args.extend(['-NextHop', via])
        if dev is not None:
            if dev.isdigit():
                args.extend(['-InterfaceIndex', dev])
            else:
                args.extend(['-InterfaceAlias', dev])
        else:
            dev = self.get_route(via)['dev']
            args.extend(['-InterfaceIndex', dev])
        if 'metric' in kwargs:
            args.extend(['-RouteMetric', int(kwargs['metric'])])
        else:
            args.extend(['-RouteMetric', 1])
        args.extend(['-PolicyStore', 'ActiveStore'])
        logger.debug("[%s] -- [%s]", args, kwargs)
        win_exec([self.ps, 'New-NetRoute'] + args, check=False)

    def replace_route(self, destination, via=None, dev=None, src=None, mtu=None, **kwargs):
        self.add_route(destination, via, dev, src, mtu, **kwargs)

    def remove_route(self, destination):
        logger = logging.getLogger(__name__)
        logger.debug("[%s]", destination)
        win_exec([self.ps, "Remove-NetRoute", '-AddressFamily', self._family_option(destination),
                  '-DestinationPrefix', destination, '-Confirm:$false'])

    def get_route(self, destination):
        logger = logging.getLogger(__name__)
        logger.debug("[%s]", destination)
        if type(destination) is IPv4Network:
            destination = destination[0]
        info = win_exec([self.ps, 'Find-NetRoute', '-RemoteIPAddress', destination])
        lines = iter(info.splitlines())
        info_d = parse_pwsh_flat_table(lines)
        return {
            'via': info_d['NextHop'],
            'dev': info_d['InterfaceIndex'],
            'metric': info_d['RouteMetric'],
        }

    def flush_cache(self):
        logger = logging.getLogger(__name__)
        logger.debug("Flushing route cache.")
        win_exec(['netsh', 'interface', 'ip', 'delete', 'destinationcache'])

    def get_link_info(self, device):
        logger = logging.getLogger(__name__)
        logger.debug("[%s]", device)
        info = win_exec([self.ps, 'Get-NetIPInterface', '-InterfaceAlias', device, "|", "Format-Table", "-AutoSize"])
        lines = iter(info.splitlines())
        records = parse_pwsh_table(lines)
        if len(records) > 0:
            record = records[0]
            return {
                "state": "UP" if "Connected" == record['ConnectionState'] else "DOWN",
                "mtu": int(record['NlMtu(Bytes)']),
            }
        return None

    def set_link_info(self, device, state, mtu=None):
        logger = logging.getLogger(__name__)
        logger.debug("[%s] -- [%s] -- [%s]", device, state, mtu)
        # the adapter is already enabled for openconnect to start
        # if state is not None:
        #     enable_adapter_args = ['Enable-NetAdapter', '-Name', device]
        #     disable_adapter_args = ['Disable-NetAdapter', '-Name', device, '-Confirm:$false']
        #     if state == 'up':
        #         win_exec([self.ps] + enable_adapter_args)
        #     else:
        #         win_exec([self.ps] + disable_adapter_args)
        if mtu is not None:
            args = ['Set-NetIPInterface']
            args.extend(('-InterfaceAlias', device))
            args.extend(("-NlMtuBytes", str(mtu)))
            args.extend(("-PolicyStore", "ActiveStore"))
            args.extend(("-InterfaceMetric", "1"))
            win_exec([self.ps] + args)

    def add_address(self, device, address):
        logger = logging.getLogger(__name__)
        logger.debug("[%s] -- [%s]", device, address)
        family = self._family_option(address)
        info = win_exec(
            [self.ps, 'Get-NetIPAddress', '-InterfaceAlias', device, '-AddressFamily', family, '|', 'Format-Table',
             '-AutoSize'])
        lines = iter(info.splitlines())
        existing_addresses = parse_pwsh_table(lines)
        for existing_address in existing_addresses:
            win_exec(
                [self.ps, 'Remove-NetIPAddress', '-PolicyStore', 'ActiveStore', '-IPAddress',
                 existing_address['IPAddress'], '-Confirm:$false'], check=False)
        win_exec(
            [self.ps, 'New-NetIPAddress', '-PolicyStore', 'ActiveStore', '-AddressFamily', family, '-InterfaceAlias',
             device, '-IPAddress', address])


class WinTunnelPrepProvider(TunnelPrepProvider):
    def __init__(self):
        self.ps = get_executable("powershell.exe")

    def pre_connect(self, env, args):
        logger = logging.getLogger(__name__)
        device = env.tundev
        # remove all existing routes for this device
        logger.debug("Removing all existing routes from 'ActiveStore' for [%s]", device)
        win_exec(
            [self.ps, 'Get-NetRoute', '-InterfaceAlias', device, '-PolicyStore', 'ActiveStore', '|', 'Remove-NetRoute',
             '-PolicyStore', 'ActiveStore', '-Confirm:$false'], check=False)
        logger.debug("Removing all existing routes from 'PersistentStore' for [%s]", device)
        win_exec(
            [self.ps, 'Get-NetRoute', '-InterfaceAlias', device, '-PolicyStore', 'PersistentStore', '|',
             'Remove-NetRoute', '-PolicyStore', 'PersistentStore', '-Confirm:$false'], check=False)


class WinDNSProvider(DNSPythonProvider):
    def __init__(self):
        self.ps = get_executable("powershell.exe")

    def configure(self, dns_servers, bind_addresses=None, search_domains=(), **kwargs):
        super().configure(dns_servers, bind_addresses, search_domains, **kwargs)
        if 'dev' in kwargs:
            dns_server_args = list(map(lambda x: '"%s"' % x, dns_servers))
            ps_dns_server_arg = '(%s)' % ','.join(dns_server_args)
            win_exec([self.ps, 'Set-DnsClientServerAddress', '-InterfaceAlias', kwargs['dev'],
                      '-ServerAddresses', ps_dns_server_arg])
