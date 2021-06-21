#!/usr/bin/env python3

from __future__ import print_function
from sys import stderr, platform
import os, subprocess as sp
import argparse
from enum import Enum
from itertools import chain, zip_longest
from ipaddress import ip_network, ip_address,  IPv4Address, IPv4Network, IPv6Address, IPv6Network, IPv6Interface
from time import sleep
from random import randint, choice, shuffle
import logging
import logging.handlers
import pathlib
from filelock import FileLock
import pprint

try:
    from setproctitle import setproctitle
except ImportError:
    def setproctitle(title):
        pass


def tagged(iter, tag):
    return zip_longest(iter, (), fillvalue=tag)


from .version import __version__
from .util import slurpy


def get_default_providers():
    global platform
    try:
        from .dnspython import DNSPythonProvider
    except ImportError:
        DNSPythonProvider = None

    if platform.startswith('linux'):
        from .linux import ProcfsProvider, Iproute2Provider, IptablesProvider, CheckTunDevProvider
        from .posix import DigProvider, PosixHostsFileProvider
        return dict(
            process=ProcfsProvider,
            route=Iproute2Provider,
            firewall=IptablesProvider,
            dns=DNSPythonProvider or DigProvider,
            hosts=PosixHostsFileProvider,
            prep=CheckTunDevProvider,
        )
    elif platform.startswith('darwin'):
        from platform import release
        from distutils.version import LooseVersion
        from .mac import PsProvider, BSDRouteProvider, MacSplitDNSProvider, PfFirewallProvider
        from .posix import PosixHostsFileProvider
        from .dnspython import DNSPythonProvider
        return dict(
            process=PsProvider,
            route=BSDRouteProvider,
            dns=DNSPythonProvider or DigProvider,
            hosts=PosixHostsFileProvider,
            domain_vpn_dns=MacSplitDNSProvider,
            firewall = PfFirewallProvider if release() >= LooseVersion('10.6') else None,
        )
    elif platform.startswith('freebsd'):
        from .mac import BSDRouteProvider
        from .freebsd import ProcfsProvider
        from .posix import PosixHostsFileProvider
        from .dnspython import DNSPythonProvider
        return dict(
            process = ProcfsProvider,
            route = BSDRouteProvider,
            dns = DNSPythonProvider or DigProvider,
            hosts = PosixHostsFileProvider,
        )
    elif platform.startswith('win'):
        from .posix import DigProvider
        from .win import Win32ProcessProvider, WinRouteProvider, WinHostsFileProvider, WinTunnelPrepProvider,\
            WinDNSProvider
        return dict(
            process=Win32ProcessProvider,
            route=WinRouteProvider,
            dns=WinDNSProvider,
            hosts=WinHostsFileProvider,
            prep=WinTunnelPrepProvider,
        )
    else:
        return dict(
            platform=OSError('Your platform, {}, is unsupported'.format(platform))
        )


def net_or_host_param(s):
    if '=' in s:
        hosts = s.split('=')
        ip = hosts.pop()
        return hosts, ip_address(ip)
    else:
        if s.lstrip().startswith('%'):
            include = False
            s = s.lstrip()[1:]
        else:
            include = True

        try:
            return include, ip_network(s, strict=False)
        except ValueError:
            return s


def names_for(host, domains, short=True, long=True):
    if '.' in host:
        first, rest = host.split('.', 1)
    else:
        first, rest = host, None
    if isinstance(domains, str): domains = (domains,)

    names = []
    if long:
        if rest:
            names.append(host)
        elif domains:
            names.append(host + '.' + domains[0])
    if short:
        if not rest:
            names.append(host)
        elif rest in domains:
            names.append(first)
    return names


########################################

def do_pre_init(env, args):
    global providers
    if 'prep' in providers:
        providers.prep.create_tunnel(env, args)
        providers.prep.prepare_tunnel(env, args)


def do_disconnect(env, args):
    logger = logging.getLogger(__name__)
    global providers
    for pidfile in args.kill:
        if not pidfile:
            continue
        try:
            pidfileentry = open(pidfile).read()
            if not pidfileentry:
                continue
            pid = int(open(pidfile).read())
        except (IOError, ValueError):
            logger.warning("WARNING: could not read pid from %s" % pidfile)
        else:
            try:
                providers.process.kill(pid)
            except OSError as e:
                logger.warning("WARNING: could not kill pid %d from %s: %s" % (pid, pidfile, str(e)))
            else:
                if args.verbose:
                    logger.warning("Killed pid %d from %s" % (pid, pidfile))

    if 'hosts' in providers:
        removed = providers.hosts.write_hosts({}, args.name)
        logger.info("Removed %d hosts from /etc/hosts" % removed)

    # delete explicit route to gateway
    try:
        providers.route.remove_route(env.gateway)
    except sp.CalledProcessError:
        logger.warning("WARNING: could not delete route to VPN gateway (%s)" % env.gateway)

    # remove firewall rule blocking incoming traffic
    if 'firewall' in providers and not args.incoming:
        try:
            providers.firewall.deconfigure_firewall(env.tundev)
        except sp.CalledProcessError:
            logger.warning("WARNING: failed to deconfigure firewall for VPN interface (%s)" % env.tundev)

    if args.vpn_domains is not None:
        try:
            providers.domain_vpn_dns.deconfigure_domain_vpn_dns(args.vpn_domains, env.dns)
        except:
            logger.warning("failed to deconfigure domains vpn dns")


def do_connect(env, args):
    logger = logging.getLogger(__name__)
    global providers
    if args.banner and env.banner:
        logger.info("Connect Banner:")
        for l in env.banner.splitlines():
            logger.info("| " + l)

    # set explicit route to gateway
    if env.gateway.is_loopback:
        logger.warning("Gateway address is loopback; probably a local proxy.")
    else:
        gwr = providers.route.get_route(env.gateway)
        if gwr:
            providers.route.replace_route(env.gateway, **gwr)
            logger.info("Set explicit route to VPN gateway %s (%s)" % (env.gateway, ', '.join('%s %s' % kv for kv in gwr.items())))
        else:
            logger.info("WARNING: no route to VPN gateway found %s; cannot set explicit route to it." % env.gateway)

    # drop incoming traffic from VPN
    if not args.incoming:
        if 'firewall' not in providers:
            logger.warning("WARNING: no firewall provider available; can't block incoming traffic")
        else:
            try:
                providers.firewall.configure_firewall(env.tundev)
                logger.info("Blocked incoming traffic from VPN interface with iptables.")
            except sp.CalledProcessError:
                try:
                    providers.firewall.deconfigure_firewall(env.tundev)
                except sp.CalledProcessError:
                    pass
                logger.warning("WARNING: failed to block incoming traffic")

    # configure MTU
    mtu = env.mtu
    if mtu is None:
        dev = gwr.get('dev')
        if dev:
            dev_mtu = providers.route.get_link_info(dev).get('mtu')
            if dev_mtu:
                mtu = int(dev_mtu) - 88
        if mtu:
            logger.warning("WARNING: guessing MTU is %d (the MTU of %s - 88)" % (mtu, dev))
        else:
            mtu = 1412
            logger.warning("WARNING: guessing default MTU of %d (couldn't determine MTU of %s)" % (mtu, dev))
    providers.route.set_link_info(env.tundev, state='up', mtu=mtu)

    # set IPv4, IPv6 addresses for tunnel device
    if env.myaddr:
        providers.route.add_address(env.tundev, env.myaddr)
    if env.myaddr6:
        providers.route.add_address(env.tundev, env.myaddr6)

    # save routes for excluded subnets
    exc_subnets = []

    for dest in args.exc_subnets:
        r = gwr
        if args.check_splits:
            r = providers.route.get_route(dest)
        if r:
            exc_subnets.append((dest, r))
        else:
            logger.warning("Ignoring unroutable split-exclude %s" % dest)

    # set up routes to the DNS and Windows name servers, subnets, and local aliases
    ns = env.dns + env.dns6 + (env.nbns if args.nbns else [])
    for dest, tag in chain(tagged(ns, "nameserver"), tagged(args.subnets, "subnet"), tagged(args.aliases, "alias")):
        logger.info("Adding route to %s %s through %s." % (tag, dest, env.tundev))
        providers.route.replace_route(dest, dev=env.tundev)
    else:
        providers.route.flush_cache()
        logger.info("Added routes for %d nameservers, %d subnets, %d aliases." % (len(ns), len(args.subnets), len(args.aliases)))

    # set the dns servers on the interface
    providers.dns.configure(dns_servers=(env.dns + env.dns6), search_domains=args.domain, bind_addresses=env.myaddrs,
                            dev=env.tundev)

    # if we did not add any route above we will add a default route with metric 5
    if not len(args.subnets):
        internal_gw = next(env.network.hosts())
        dest = ip_network('0.0.0.0/0')
        logger.info("Adding route to %s %s through %s." % ('default', dest, internal_gw))
        providers.route.replace_route(dest, dev=env.tundev, via=internal_gw, metric=1)

    # restore routes to excluded subnets
    for dest, exc_route in exc_subnets:
        providers.route.replace_route(dest, **exc_route)
        logger.warning("Restoring split-exclude route to %s (%s)" % (dest, ', '.join('%s %s' % kv for kv in exc_route.items())))
    else:
        providers.route.flush_cache()
        logger.warning("Restored routes for %d excluded subnets %s.", len(exc_subnets), exc_subnets)

    # Use vpn dns for provided domains
    if args.vpn_domains is not None:
        if 'domain_vpn_dns' not in providers:
            logger.warning("no split dns provider available; can't split dns")
        else:
            providers.domain_vpn_dns.configure_domain_vpn_dns(args.vpn_domains, env.dns)


def do_post_connect(env, args):
    logger = logging.getLogger(__name__)
    global providers
    # lookup named hosts for which we need routes and/or host_map entries
    # (the DNS/NBNS servers already have their routes)
    ip_routes = set()
    host_map = []

    if args.ns_hosts:
        ns_names = [(ip, ('dns%d.%s' % (ii, args.name),)) for ii, ip in enumerate(env.dns + env.dns6)]
        if args.nbns:
            ns_names += [(ip, ('nbns%d.%s' % (ii, args.name),)) for ii, ip in enumerate(env.nbns)]
        host_map += ns_names
        logger.info("Adding /etc/hosts entries for %d nameservers..." % len(ns_names))
        for ip, names in ns_names:
            logger.info("  %s = %s" % (ip, ', '.join(map(str, names))))

    logger.info("Looking up %d hosts using VPN DNS servers..." % len(args.hosts))
    providers.dns.configure(dns_servers=(env.dns + env.dns6), search_domains=args.domain, bind_addresses=env.myaddrs)
    for host in args.hosts:
        try:
            ips = providers.dns.lookup_host(host)
        except Exception as e:
            logger.warning("WARNING: Lookup for %s on VPN DNS servers failed:\n\t%s" % (host, e))
        else:
            if ips is None:
                logger.warning("WARNING: Lookup for %s on VPN DNS servers returned nothing." % host)
            else:
                logger.info("  %s = %s" % (host, ', '.join(map(str, ips))))
                ip_routes.update(ips)
                if args.host_names:
                    names = names_for(host, args.domain, args.short_names)
                    host_map.extend((ip, names) for ip in ips)
    for ip, aliases in args.aliases.items():
        host_map.append((ip, aliases))

    # add them to /etc/hosts
    if host_map:
        providers.hosts.write_hosts(host_map, args.name)
        logger.info("Added hostnames and aliases for %d addresses to /etc/hosts." % len(host_map))

    # add routes to hosts
    for ip in ip_routes:
        logger.info("Adding route to %s (for named hosts) through %s." % (ip, env.tundev))
        providers.route.replace_route(ip, dev=env.tundev)
    else:
        providers.route.flush_cache()
        logger.info("Added %d routes for named hosts." % len(ip_routes))

    # run DNS queries in background to prevent idle timeout
    if args.prevent_idle_timeout:
        dev = env.tundev
        dns = (env.dns + env.dns6)
        idle_timeout = env.idle_timeout
        setproctitle('vpn-slice --prevent-idle-timeout --name %s' % args.name)
        logger.info("Continuing in background as PID %d, attempting to prevent idle timeout every %d seconds." % (
            providers.process.pid(), idle_timeout))

        while True:
            delay = randint(2 * idle_timeout // 3, 9 * idle_timeout // 10)
            logger.info("Sleeping %d seconds until we issue a DNS query to prevent idle timeout..." % delay)
            sleep(delay)

            # FIXME: netlink(7) may be a much better way to poll here
            if not providers.process.is_alive(args.ppid):
                logger.warning("Caller (PID %d) has terminated; idle preventer exiting." % args.ppid)
                break

            # pick random host or IP to look up without leaking any new information
            # about what we do/don't access within the VPN
            pool = args.hosts
            pool += map(str, chain(env.dns, env.dns6, env.nbns,
                                   ((r.network_address) for r in args.subnets if r.prefixlen == r.max_prefixlen)))
            dummy = choice(pool)
            shuffle(dns)
            logger.info("Issuing DNS lookup of %s to prevent idle timeout..." % dummy)
            providers.dns.lookup_host(dummy, keep_going=False)

    logger.info("Connection setup done, child process %d exiting." % providers.process.pid())


########################################

# Translate environment variables which may be passed by our caller
# into a more Pythonic form (these are take from vpnc-script)
reasons = Enum('reasons', 'pre_init connect disconnect reconnect attempt_reconnect')
vpncenv = [
    ('reason', 'reason', lambda x: reasons[x.replace('-', '_')]),
    ('gateway', 'VPNGATEWAY', ip_address),
    ('tundev', 'TUNDEV', str),
    ('domain', 'CISCO_DEF_DOMAIN', lambda x: x.split(), []),
    ('splitdns','CISCO_SPLIT_DNS',lambda x: x.split(','),[]),
    ('banner', 'CISCO_BANNER', str),
    ('myaddr', 'INTERNAL_IP4_ADDRESS', IPv4Address),  # a.b.c.d
    ('mtu', 'INTERNAL_IP4_MTU', int),
    ('netmask', 'INTERNAL_IP4_NETMASK', IPv4Address),  # a.b.c.d
    ('netmasklen', 'INTERNAL_IP4_NETMASKLEN', int),
    ('network', 'INTERNAL_IP4_NETADDR', IPv4Address),  # a.b.c.d
    ('dns', 'INTERNAL_IP4_DNS', lambda x: [ip_address(x) for x in x.split()], []),
    ('nbns', 'INTERNAL_IP4_NBNS', lambda x: [IPv4Address(x) for x in x.split()], []),
    ('myaddr6', 'INTERNAL_IP6_ADDRESS', IPv6Interface),  # x:y::z or x:y::z/p
    ('netmask6', 'INTERNAL_IP6_NETMASK', IPv6Interface),  # x:y:z:: or x:y::z/p
    ('dns6', 'INTERNAL_IP6_DNS', lambda x: [ip_address(x) for x in x.split()], []),
    ('nsplitinc', 'CISCO_SPLIT_INC', int, 0),
    ('nsplitexc', 'CISCO_SPLIT_EXC', int, 0),
    ('nsplitinc6', 'CISCO_IPV6_SPLIT_INC', int, 0),
    ('nsplitexc6', 'CISCO_IPV6_SPLIT_EXC', int, 0),
    ('idle_timeout', 'IDLE_TIMEOUT', int, 600),
]


def parse_env(environ=os.environ):
    logger = logging.getLogger(__name__)
    global vpncenv
    env = slurpy()
    for var, envar, maker, *default in vpncenv:
        if envar in environ:
            try:
                val = maker(environ[envar])
            except Exception as e:
                logger.warning('Exception while setting %s from environment variable %s=%r' % (var, envar, environ[envar]))
                raise
        elif default:
            val, = default
        else:
            val = None
        if var is not None: env[var] = val

    # IPv4 network is the combination of the network address (e.g. 192.168.0.0) and the netmask (e.g. 255.255.0.0)
    if env.network:
        orig_netaddr = env.network
        env.network = IPv4Network(env.network).supernet(new_prefix=env.netmasklen)
        if env.network.network_address != orig_netaddr:
            logger.warning("WARNING: IPv4 network %s/%d has host bits set, replacing with %s" % (orig_netaddr, env.netmasklen, env.network))
        if env.network.netmask != env.netmask:
            raise AssertionError(
                "IPv4 network (INTERNAL_IP4_{{NETADDR,NETMASK}}) {ad}/{nm} does not match INTERNAL_IP4_NETMASKLEN={nml} (implies /{nmi})".format(
                    ad=orig_netaddr, nm=env.netmask, nml=env.netmasklen, nmi=env.network.netmask))
        assert env.network.netmask == env.netmask

    # Need to match behavior of original vpnc-script here
    # Examples:
    #   1) INTERNAL_IP6_ADDRESS=fe80::1, INTERNAL_IP6_NETMASK=fe80::/64  => interface of fe80::1/64,  network of fe80::/64
    #   2) INTERNAL_IP6_ADDRESS=unset,   INTERNAL_IP6_NETMASK=fe80::1/64 => interface of fe80::1/64,  network of fe80::/64
    #   3) INTERNAL_IP6_ADDRESS=2000::1, INTERNAL_IP6_NETMASK=unset      => interface of 2000::1/128, network of 2000::1/128
    if env.myaddr6 or env.netmask6:
        if not env.netmask6:
            env.netmask6 = IPv6Network(env.myaddr6)  # case 3 above, /128
        env.myaddr6 = IPv6Interface(env.netmask6)
        env.network6 = env.myaddr6.network
    else:
        env.myaddr6 = None
        env.network6 = None

    env.myaddrs = list(filter(None, (env.myaddr, env.myaddr6)))

    # Handle splits
    env.splitinc = []
    env.splitexc = []
    for pfx, n in chain((('INC', n) for n in range(env.nsplitinc)),
                        (('EXC', n) for n in range(env.nsplitexc))):
        ad = IPv4Address(environ['CISCO_SPLIT_%s_%d_ADDR' % (pfx, n)])
        nm = IPv4Address(environ['CISCO_SPLIT_%s_%d_MASK' % (pfx, n)])
        nml = int(environ['CISCO_SPLIT_%s_%d_MASKLEN' % (pfx, n)])
        net = IPv4Network(ad).supernet(new_prefix=nml)
        if net.network_address != ad:
            logger.warning("WARNING: IPv4 split network (CISCO_SPLIT_%s_%d_{ADDR,MASK}) %s/%d has host bits set, replacing with %s" % (pfx, n, ad, nml, net))
        if net.netmask != nm:
            raise AssertionError("IPv4 split network (CISCO_SPLIT_{pfx}_{n}_{{ADDR,MASK}}) {ad}/{nm} does not match CISCO_SPLIT_{pfx}_{n}_MASKLEN={nml} (implies /{nmi})".format(
                    pfx=pfx, n=n, ad=ad, nm=nm, nml=nml, nmi=net.netmask))
        env['split' + pfx.lower()].append(net)

    for pfx, n in chain((('INC', n) for n in range(env.nsplitinc6)),
                        (('EXC', n) for n in range(env.nsplitexc6))):
        ad = IPv6Address(environ['CISCO_IPV6_SPLIT_%s_%d_ADDR' % (pfx, n)])
        nml = int(environ['CISCO_IPV6_SPLIT_%s_%d_MASKLEN' % (pfx, n)])
        net = IPv6Network(ad).supernet(new_prefix=nml)
        if net.network_address != ad:
            logger.warning("WARNING: IPv6 split network (CISCO_IPV6_SPLIT_%s_%d_{ADDR,MASKLEN}) %s/%d has host bits set, replacing with %s" % (pfx, n, ad, nml, net))
        env['split' + pfx.lower()].append(net)

    return env


config_args = [
    ('routes', lambda config: [net_or_host_param(s) for s in config['routes']]),
    ('fork', lambda config: config['subprocess']['fork']),
    ('kill', lambda config: config['subprocess']['kill']),
    ('prevent_idle_timeout', lambda config: config['subprocess']['prevent_idle_timeout']),
    ('banner', lambda config: config['info']['banner']),
    ('incoming', lambda config: config['routing']['incoming']),
    ('name', lambda config: config['routing']['name']),
    ('domain', lambda config: config['routing']['domain']),
    ('route_internal', lambda config: config['routing']['internal']),
    ('route_splits', lambda config: config['routing']['splits']),
    ('host_names', lambda config: config['routing']['host_names']),
    ('short_names', lambda config: config['routing']['short_names']),
    ('ns_hosts', lambda config: config['nameserver']['ns_hosts']),
    ('nbns', lambda config: config['nameserver']['nbns']),
    ('dump', lambda config: config['debug']['dump']),
    ('verbose', lambda config: config['debug']['verbose']),
    ('debug', lambda config: config['debug']['debug']),
    ('check_splits', lambda config: config['routing']['check_splits'])
]


def load_config(config_path, args):
    logger = logging.getLogger(__name__)
    if not config_path.exists():
        return
    import toml
    with config_path.open() as config_handle:
        config = toml.load(config_handle)
    for arg, maker in config_args:
        try:
            val = maker(config)
            args.__setattr__(arg, val)
        except KeyError:
            logger.debug("Could not find arg [%s] in config", arg)


# Parse command-line arguments and environment
def parse_args_and_env(args=None, environ=os.environ):
    p = argparse.ArgumentParser()
    p.add_argument('routes', nargs='*', type=net_or_host_param,
                   help='List of VPN-internal hostnames, included subnets (e.g. 192.168.0.0/24), '
                        'excluded subnets (e.g. %%8.0.0.0/8), or aliases (e.g. host1=192.168.1.2) '
                        'to add to routing and /etc/hosts.')
    p.add_argument('-c', '--config', type=pathlib.Path,
                   default=pathlib.Path(os.path.expanduser("~/.config/vpn-slice/config.toml")),
                   required=False)
    g = p.add_argument_group('Subprocess options')
    g.add_argument('-k', '--kill', default=[], action='append',
                   help='File containing PID to kill before disconnect (may be specified multiple times)')
    g.add_argument('-K', '--prevent-idle-timeout', action='store_true',
                   help='Prevent idle timeout by doing random DNS lookups (interval set by $IDLE_TIMEOUT, '
                        'defaulting to 10 minutes)')
    g = p.add_argument_group('Informational options')
    g.add_argument('--banner', action='store_true', help='Print banner message (default is to suppress it)')
    g = p.add_argument_group('Routing and hostname options')
    g.add_argument('-i', '--incoming', action='store_true',
                   help='Allow incoming traffic from VPN (default is to block)')
    g.add_argument('-n', '--name', default=None, help='Name of this VPN (default is $TUNDEV)')
    g.add_argument('-d', '--domain', action='append',
                   help='Search domain inside the VPN (default is $CISCO_DEF_DOMAIN)')
    g.add_argument('-I', '--route-internal', action='store_true',
                   help="Add route for VPN's default subnet (passed in as $INTERNAL_IP*_NET*")
    g.add_argument('-S', '--route-splits', action='store_true',
                   help="Add route for VPN's split-tunnel subnets (passed in via $CISCO_SPLIT_*)")
    g.add_argument('--no-host-names', action='store_false', dest='host_names', default=True,
                   help='Do not add either short or long hostnames to /etc/hosts')
    g.add_argument('--no-short-names', action='store_false', dest='short_names', default=True,
                   help="Only add long/fully-qualified domain names to /etc/hosts")
    g = p.add_argument_group('Nameserver options')
    g.add_argument('--no-ns-hosts', action='store_false', dest='ns_hosts', default=True,
                   help='Do not add nameserver aliases to /etc/hosts (default is to name them dns0.tun0, etc.)')
    g.add_argument('--nbns', action='store_true', dest='nbns',
                   help='Include NBNS (Windows/NetBIOS nameservers) as well as DNS nameservers')
    g.add_argument('--domains-vpn-dns', dest='vpn_domains', default=None, help="comma seperated domains to query "
                                                                               "with vpn dns")
    g.add_argument('--no-check-splits', dest='check_splits', default=True, help="check split routes for validity.")
    g = p.add_argument_group('Debugging options')
    g.add_argument('--self-test', action='store_true',
                   help='Stop after verifying that environment variables and providers are configured properly.')
    g.add_argument('-v', '--verbose', default=0, action='count', help="Explain what %(prog)s is doing")
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    g.add_argument('-D', '--dump', default=True, action='store_false', help='Dump environment variables passed by caller')
    g.add_argument('--no-fork', action='store_false', dest='fork', help="Don't fork and continue in background on connect")
    g.add_argument('--ppid', type=int, help='PID of calling process (normally autodetected, when using openconnect or vpnc)')
    g.add_argument('--debug', action='store_true', default=False, help="Connect using pycharm remote debug.")
    args = p.parse_args(args)
    logger = logging.getLogger(__name__)
    if 'config' in args and args.config is not None and args.config.exists():
        logger.info("Trying to load config from file. [%s].", args.config)
        load_config(args.config, args)
    elif 'VPN_SLICE_CONFIG' in environ:
        logger.info("Trying to load config from environment. [%s]", environ['VPN_SLICE_CONFIG'])
        load_config(pathlib.Path(environ['VPN_SLICE_CONFIG']), args)

    env = parse_env(environ)
    return p, args, env


def finalize_args_and_env(args, env):
    global providers

    # use the tunnel device as the VPN name if unspecified
    if args.name is None:
        args.name = env.tundev

    # autodetect parent or grandparent process (skipping intermediary shell)
    # it finds pid of openconnect or vpnc
    # for mac and linux
    # openconenct -> shell -> python (vpn-slice)
    # windows
    # openconnect -> shell -> cscript -> shell -> python (vpn-slice)
    if args.ppid is None:
        args.ppid = providers.process.get_caller()

    # use the list from the env if --domain wasn't specified, but start with an
    # empty list if it was specified; hence can't use 'default' here:
    if args.domain is None:
        args.domain = env.domain

    args.subnets = []
    args.exc_subnets = []
    args.hosts = []
    args.aliases = {}
    for x in args.routes:
        if isinstance(x, str):
            args.hosts.append(x)
        elif x[0] in (True, False):
            include, net = x
            if include:
                args.subnets.append(net)
            else:
                args.exc_subnets.append(net)
        else:
            hosts, ip = x
            args.aliases.setdefault(ip, []).extend(hosts)
    if args.route_internal:
        if env.network: args.subnets.append(env.network)
        if env.network6: args.subnets.append(env.network6)
    if args.route_splits:
        args.subnets.extend(env.splitinc)
        args.exc_subnets.extend(env.splitexc)
    if args.vpn_domains is not None:
        args.vpn_domains = str.split(args.vpn_domains, ',')


def main(args=None, environ=os.environ):
    global providers
    logger = logging.getLogger(__name__)
    logger.info("---------------------------------------------------")
    logger.info("---------- STARTING VPN SLICE ---------------------")
    logger.info("---------------------------------------------------")

    try:
        p, args, env = parse_args_and_env(args, environ)
        if args.debug:
            import pydevd_pycharm
            pydevd_pycharm.settrace('localhost', port=9000, stdoutToServer=True, stderrToServer=True)

        # Set platform-specific providers
        providers = slurpy()
        for pn, pv in get_default_providers().items():
            try:
                if isinstance(pv, Exception):
                    raise pv
                providers[pn] = pv()
            except Exception as e:
                logger.warning("WARNING: Couldn't configure {} provider: {}".format(pn, e))

        # Finalize arguments that depend on providers
        finalize_args_and_env(args, env)

        # Fail if necessary providers are missing
        required = {'route', 'process'}
        # The hosts provider is required unless:
        #   1) '--no-ns-hosts --no-host-names' specified, or
        #   2) '--no-ns-hosts' specified, but neither hosts nor aliases specified
        if not args.ns_hosts and not args.host_names:
            pass
        elif not args.ns_hosts and not args.hosts and not args.aliases:
            pass
        else:
            required.add('hosts')
        # The DNS provider is required if:
        #   1) Any hosts are specified
        #   2) '--prevent-idle-timeout' is specified
        if args.hosts or args.prevent_idle_timeout:
            required.add('dns')
        missing_required = {p for p in required if p not in providers}
        if missing_required:
            raise RuntimeError(
                "Aborting because providers for %s are required; use --help for more information" % ' '.join(
                    missing_required))

    except Exception as e:
        if args.self_test:
            logger.info('******************************************************************************************')
            logger.info('*** Self-test did not pass. Double-check that you are running as root (e.g. with sudo) ***')
            logger.info('******************************************************************************************')
        raise SystemExit(*e.args)

    else:
        if args.self_test:
            logger.info('***************************************************************************')
            logger.info('*** Self-test passed. Try using vpn-slice with openconnect or vpnc now. ***')
            logger.info('***************************************************************************')
            raise SystemExit()

    if env.myaddr6 or env.netmask6:
        logger.info('WARNING: IPv6 address or netmask set. Support for IPv6 in %s should be considered BETA-QUALITY.' % p.prog)
    if args.dump:
        exe = providers.process.pid2exe(args.ppid)
        caller = '%s (PID %d)'%(exe, args.ppid) if exe else 'PID %d' % args.ppid

        logger.info('Called by %s with environment variables for vpnc-script:' % caller)
        width = max((len(envar) for var, envar, *rest in vpncenv if envar in environ), default=0)
        for var, envar, *rest in vpncenv:
            if envar in environ:
                pyvar = var+'='+repr(env[var]) if var else 'IGNORED'
                logger.info('  %-*s => %s' % (width, envar, pyvar))
        if env.splitinc:
            logger.info('  %-*s => %s=%r' % (width, 'CISCO_*SPLIT_INC_*', 'splitinc', env.splitinc))
        if env.splitexc:
            logger.info('  %-*s => %s=%r' % (width, 'CISCO_*SPLIT_EXC_*', 'splitexc', env.splitexc))
        if args.subnets:
            logger.info('Complete set of subnets to include in VPN routes:')

            logger.info('  ' + '\n  '.join(map(str, args.subnets)))
        if args.exc_subnets:
            logger.info('Complete set of subnets to exclude from VPN routes:')
            logger.info('  ' + '\n  '.join(map(str, args.exc_subnets)))
        if args.aliases:
            logger.info('Complete set of host aliases to add /etc/hosts entries for:')
            logger.info('  ' + '\n  '.join(args.aliases))
        if args.hosts:
            logger.info('Complete set of host names to include in VPN routes after DNS lookup%s:' % (' (and add /etc/hosts entries for)' if args.host_names else ''))
            logger.info('  ' + '\n  '.join(args.hosts))

    logger.info("Args : [%s]" % pprint.pformat(args))
    logger.info("Env : [%s]" % pprint.pformat(env))

    if env.reason is None:
        raise SystemExit("Must be called as vpnc-script, with $reason set; use --help for more information")
    elif env.reason == reasons.pre_init:
        do_pre_init(env, args)
    elif env.reason == reasons.disconnect:
        do_disconnect(env, args)
    elif env.reason == reasons.reconnect:
        do_post_connect(env, args)
    elif env.reason == reasons.attempt_reconnect:
        # FIXME: is there anything that reconnect or attempt_reconnect /should/ do
        # on a modern system (Linux) which automatically removes routes to
        # a tunnel adapter that has been removed? I am not clear on whether
        # any other behavior is potentially useful.
        #
        # See these issue comments for some relevant discussion:
        #   https://gitlab.com/openconnect/openconnect/issues/17#note_131764677
        #   https://github.com/dlenski/vpn-slice/pull/14#issuecomment-488129621

        if args.verbose:
            logger.warninig('WARNING: %s ignores reason=%s' % (p.prog, env.reason.name))
    elif env.reason == reasons.connect:
        if 'prep' in providers:
            providers.prep.pre_connect(env, args)
        do_connect(env, args)
        # we continue running in a new child process, so the VPN can actually
        # start in the background, because we need to actually send traffic to it
        # do not try to fork on windows
        if not platform.startswith('win') and args.fork and os.fork():
            raise SystemExit

        do_post_connect(env, args)
    logger.info("---------------------------------------------------")
    logger.info("---------- FINISHED VPN SLICE ---------------------")
    logger.info("---------------------------------------------------")


if __name__ == '__main__':
    log_file_name = 'vpnc.log'
    need_new_log_file = os.path.isfile(log_file_name)
    handler = logging.handlers.RotatingFileHandler(filename=log_file_name, backupCount=5)
    if need_new_log_file:
        handler.doRollover()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(funcName)s %(message)s',
                        handlers=[handler])
    logger = logging.getLogger(__name__)
    lock = FileLock("vpnc.lock")
    with lock:
        try:
            main()
        except:
            logger.error("Failed executing vpnc.", exc_info=True)
            raise
