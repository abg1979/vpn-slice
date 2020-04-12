import fcntl

from .crossos import CrossOsHostsFileProvider


class PosixHostsFileProvider(CrossOsHostsFileProvider):
    def __init__(self):
        super().__init__("/etc/hosts")

    def lock_hosts_file(self, hostf):
        fcntl.flock(hostf, fcntl.LOCK_EX)
