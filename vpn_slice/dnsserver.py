#!/usr/bin/env python3.6
import logging
from datetime import datetime
from textwrap import wrap
import time

from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer, BaseResolver

from typing import List
from re import Pattern
from queue import Queue
import threading

SERIAL_NO = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())

TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}


class Record:
    def __init__(self, rname, rtype, args):
        self._rname = DNSLabel(rname)

        rd_cls, self._rtype = TYPE_LOOKUP[rtype]

        if self._rtype == QTYPE.SOA and len(args) == 2:
            # add sensible times to SOA
            args += (SERIAL_NO, 3600, 3600 * 3, 3600 * 24, 3600),

        if self._rtype == QTYPE.TXT and len(args) == 1 and isinstance(args[0], str) and len(args[0]) > 255:
            # wrap long TXT records as per dnslib's docs.
            args = wrap(args[0], 255),

        if self._rtype in (QTYPE.NS, QTYPE.SOA):
            ttl = 3600 * 24
        else:
            ttl = 300

        self.rr = RR(
            rname=self._rname,
            rtype=self._rtype,
            rdata=rd_cls(*args),
            ttl=ttl,
        )

    def match(self, q):
        return q.qname == self._rname and (q.qtype == QTYPE.ANY or q.qtype == self._rtype)

    def sub_match(self, q):
        return self._rtype == QTYPE.SOA and q.qname.matchSuffix(self._rname)

    def __str__(self):
        return str(self.rr)


class MultiUpstreamResolver(BaseResolver):

    def resolve(self, request, handler):
        for upstream_proxy_resolver in self._upstream_proxy_resolvers:
            reply = upstream_proxy_resolver.resolve(request, handler)
            if reply.rr:
                return reply
        return super().resolve(request, handler)

    def __init__(self, upstream_servers: List[str] = None) -> None:
        super().__init__()
        self._upstream_servers = upstream_servers
        self._upstream_proxy_resolvers: List[ProxyResolver] = []
        self._configure()

    @property
    def upstream_servers(self):
        return self._upstream_servers

    @upstream_servers.setter
    def upstream_servers(self, upstream_servers):
        self._upstream_servers = upstream_servers
        self._configure()

    def _configure(self):
        self._upstream_proxy_resolvers = []
        for upstream_server in self._upstream_servers:
            upstream_ip, _, upstream_port = upstream_server.partition(':')
            if not upstream_port:
                upstream_port = "53"
            self._upstream_proxy_resolvers.append(ProxyResolver(upstream_ip, int(upstream_port), 5))


class DNSRouteProvider(BaseResolver):

    def resolve(self, request, handler):
        logger = logging.getLogger(__name__)
        logger.info("Looking up [%s].", request.q)
        qname = request.q.qname
        if qname and self.host_patterns is not None:
            for host_pattern in self.host_patterns:
                if host_pattern.match(qname):
                    logger.info("[%s] matches [%s]", request.q, host_pattern)
                    # should go to vpn
                    reply = self.vpn.resolve(request, handler)
                    if reply.rr and self.queue:
                        self.queue.put(reply.rr)
                    return reply
        logger.info("Looking up in upstream resolvers [%s]", request.q)
        return self.upstream.resolve(request, handler)

    def __init__(self) -> None:
        super().__init__()
        self._vpn_resolver: MultiUpstreamResolver = None
        self._upstream_resolver: MultiUpstreamResolver = None
        self._host_patterns: List[Pattern] = None
        self._queue: Queue = None

    @property
    def upstream(self) -> MultiUpstreamResolver:
        return self._upstream_resolver

    @upstream.setter
    def upstream(self, upstream_resolver: MultiUpstreamResolver):
        self._upstream_resolver = upstream_resolver

    @property
    def vpn(self) -> MultiUpstreamResolver:
        return self._vpn_resolver

    @vpn.setter
    def vpn(self, vpn_resolver: MultiUpstreamResolver):
        self._vpn_resolver = vpn_resolver

    @property
    def host_patterns(self) -> List[Pattern]:
        return self._host_patterns

    @host_patterns.setter
    def host_patterns(self, host_patterns: List[Pattern]):
        self._host_patterns = host_patterns

    @property
    def queue(self):
        return self._queue

    @queue.setter
    def queue(self, queue):
        self._queue = queue


class DNSServerProvider(object):

    def __init__(self) -> None:
        super().__init__()
        self._udp_server: DNSServer = None
        self._tcp_server: DNSServer = None
        self._route_provider: DNSRouteProvider = None
        self._queue:Queue = None
        self._providers = None
        self._continue = False
        self._thread = None

    @property
    def udp_server(self) -> DNSServer:
        return self._udp_server

    @property
    def tcp_server(self) -> DNSServer:
        return self._tcp_server

    @udp_server.setter
    def udp_server(self, udp_server: DNSServer):
        self._udp_server = udp_server

    @tcp_server.setter
    def tcp_server(self, tcp_server: DNSServer):
        self._tcp_server = tcp_server

    def configure(self, upstream_servers: List[str] = None, vpn_servers: List[str] = None,
                  host_patterns: List[Pattern] = None, port=53, providers=None):
        upstream_resolver = MultiUpstreamResolver(upstream_servers)
        vpn_resolver = MultiUpstreamResolver(vpn_servers)
        self._route_provider: DNSRouteProvider = DNSRouteProvider()
        self._route_provider.vpn = vpn_resolver
        self._route_provider.upstream = upstream_resolver
        self._route_provider.host_patterns = host_patterns
        if providers:
            self._queue = Queue()
            self._route_provider.queue = self._queue
            self._providers = providers
        self.udp_server = DNSServer(self._route_provider, port=port)
        self.tcp_server = DNSServer(self._route_provider, port=port, tcp=True)

    def start_queue_thread(self):
        self._continue = True
        self._thread = threading.Thread(target=self.consume_queue)
        self._thread.daemon = True
        self._thread.start()

    def consume_queue(self):
        while self._continue:
            rr = self._queue.get(block=True, timeout=0.5)
            if rr:
                # create route to vpn interface
                pass

    def start(self):
        logger = logging.getLogger(__name__)
        logger.info('starting DNS server.')
        self.udp_server.start_thread()
        self.tcp_server.start_thread()

    def stop(self):
        logger = logging.getLogger(__name__)
        logger.info('stopping DNS server.')
        self.tcp_server.stop()
        self.udp_server.stop()
        self._continue = False


def main():
    upstream_servers = ["192.168.10.20:53"]
    vpn_servers = []
    host_patterns = None
    port = 53
    provider = DNSServerProvider()
    provider.configure(upstream_servers=upstream_servers, vpn_servers=vpn_servers, host_patterns=host_patterns,
                       port=port)
    provider.start()
    while True:
        time.sleep(0.2)


if __name__ == '__main__':
    main()
