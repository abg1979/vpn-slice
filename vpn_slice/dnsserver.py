#!/usr/bin/env python3.6
import logging
import os
import signal
from datetime import datetime
from textwrap import wrap
from time import sleep

from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer, BaseResolver

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
        for upstream_proxy_resolver in self.upstream_proxy_resolvers:
            reply = upstream_proxy_resolver.resolve(request, handler)
            if reply.rr:
                return reply
        return super().resolve(request, handler)

    def __init__(self, upstream_servers) -> None:
        super().__init__()
        self.upstream_proxy_resolvers = []
        for upstream_server in upstream_servers:
            upstream_ip, _, upstream_port = upstream_server.partition(':')
            self.upstream_proxy_resolvers.append(ProxyResolver(upstream_ip,int(upstream_port),5))


class DNSRouteProvider(BaseResolver):

    def resolve(self, request, handler):
        qname = request.q.qname
        if qname:


        return super().resolve(request, handler)

    def __init__(self, env, args, upstream_resolver, vpn_resolver) -> None:
        super().__init__()
        self.env = env
        self.args = args
        self.upstream_resolver = upstream_resolver
        self.vpn_resolver = vpn_resolver


class DNSServerProvider(object):

    def __init__(self, env, args, upstream_servers, vpn_servers, port=53) -> None:
        super().__init__()
        upstream_resolver = MultiUpstreamResolver(upstream_servers)
        vpn_resolver = MultiUpstreamResolver(vpn_servers)
        self.route_provider = DNSRouteProvider(env, args, upstream_resolver, vpn_resolver)
        self.udp_server = DNSServer(self.route_provider, port=port)
        self.tcp_server = DNSServer(self.route_provider, port=port, tcp=True)

    def start(self):
        logger = logging.getLogger(__name__)
        logger.info('starting DNS server.')
        self.udp_server.start_thread()
        self.tcp_server.start_thread()
