import os
import pathlib
import re
import subprocess
from ipaddress import ip_network

from .crossos import CrossOsHostsFileProvider, CrossOsProcessProvider
from .provider import RouteProvider
from .util import get_executable


# DONE
class Win32ProcessProvider(CrossOsProcessProvider):
    # DONE
    def __init__(self):
        self.ps = get_executable("powershell.exe")

    # DONE
    def pid2exe(self, pid):
        info = subprocess.check_output(
            [
                self.ps,
                "Get-CimInstance",
                "Win32_Process",
                "-Filter",
                "ProcessId=" + str(pid),
                "|",
                "select",
                "Path",
            ],
            universal_newlines=True,
        )
        try:
            return info.splitlines()[3]
        except IndexError:
            return None

    # DONE
    def ppid_of(self, pid=None):
        if pid is None:
            return os.getppid()
        info = subprocess.check_output(
            [
                self.ps,
                "Get-CimInstance",
                "Win32_Process",
                "-Filter",
                "ProcessId=" + str(pid),
                "|",
                "select",
                "ParentProcessId",
            ]
        )
        try:
            return int(info.splitlines()[3])
        except IndexError:
            return None


# DONE
class WinHostsFileProvider(CrossOsHostsFileProvider):
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
    def lock_hosts_file(self, hostf):
        pass


class WinRouteProvider(RouteProvider):
    # DONE
    def __init__(self):
        self.wsl = get_executable("wsl.exe")
        self.route = get_executable("route.exe")
        self.ipconfig = get_executable("ipconfig.exe")
        self.iproute = [get_executable("wsl.exe"), "ip"]

    def _iproute(self, *args, **kwargs):
        cl = self.iproute
        cl.extend(str(v) for v in args if v is not None)
        for k, v in kwargs.items():
            if v is not None:
                cl.extend((k, str(v)))

        if args[:2] == ("route", "get"):
            output_start, keys = 1, ("via", "dev", "src", "mtu")
        elif args[:2] == ("link", "show"):
            output_start, keys = 3, ("state", "mtu")
        else:
            output_start = None

        if output_start is not None:
            words = subprocess.check_output(cl, universal_newlines=True).split()
            return {
                words[i]: words[i + 1]
                for i in range(output_start, len(words), 2)
                if words[i] in keys
            }
        else:
            subprocess.check_call(cl)

    # DONE
    def _wsl_route(self, *args):
        print(args)
        return subprocess.check_output(
            [self.wsl, "ip", "route"] + list(map(str, args)), universal_newlines=True
        )

    def _win_route(self, *args):
        return subprocess.check_output(
            [self.route] + list(map(str, args)), universal_newlines=True
        )

    # DONE
    def _ipconfig(self, *args):
        return subprocess.check_output(
            [self.ipconfig, "/all"] + list(map(str, args)), universal_newlines=True
        )

    # DONE
    def _family_option(self, destination):
        return "-6" if destination.version == 6 else "-4"

    # TODO, https://superuser.com/questions/925790/what-is-the-unix-equivalent-to-windows-command-route-add
    # TODO destination can be IP or IP with mask, convert that
    def add_route(self, destination, *, via=None, dev=None, src=None, mtu=None):
        args = ["add", self._family_option(destination)]
        if mtu is not None:
            pass  # https://serverfault.com/questions/878132
        if via is not None:
            args.extend((destination, via))
        elif dev is not None:
            args.extend(("-interface", destination, dev))
        print("add", destination, via, dev, src, mtu)
        # self._route(*args)

    replace_route = add_route

    # DONE
    def remove_route(self, destination):
        print("delete", destination)
        # self._route("delete", self._family_option(destination), destination)

    # DONE
    def get_route(self, destination):
        return self._iproute("route", "get", destination)

    # TODO https://stackoverflow.com/questions/9739156/how-to-flush-route-table-in-windows/17860876
    def flush_cache(self):
        pass

    _LINK_INFO_RE = re.compile(r"flags=\d<(.*?)>\smtu\s(\d+)$")

    # TODO
    def get_link_info(self, device):
        print("get_link_info", device)
        return
        info = self._ifconfig(device)
        match = self._LINK_INFO_RE.search(info)
        if match:
            flags = match.group(1).split(",")
            mtu = int(match.group(2))
            return {
                "state": "UP" if "UP" in flags else "DOWN",
                "mtu": mtu,
            }
        return None

    # TODO
    def set_link_info(self, device, state, mtu=None):
        print("set_link_info", device, state, mtu)
        return
        args = [device]
        if state is not None:
            args.append(state)
        if mtu is not None:
            args.extend(("mtu", str(mtu)))
        self._ifconfig(*args)

    # TODO
    def add_address(self, device, address):
        print("add_address", device, address)
        return
        if address.version == 6:
            family = "inet6"
        else:
            family = "inet"
        self._ifconfig(device, family, ip_network(address), address)
