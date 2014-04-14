#!/usr/bin/env python
"""
check-dnsbl.py: checks a list of DNS blocklists for hosts and IPs.
Given any hostname or IP address, this will try to resolve the matching
IP/hostname, and check for both in all blocklists. For every match that
is found, a warning is written to STDERR, and the return code will be 1.
Gevent is used for concurrent lookups, the number of active greenlets
is limited to PARALLELISM.

Inspired by https://github.com/DjinnS/check-rbl
Hosted at https://github.com/andreasf/check-dnsbl

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from gevent import monkey
monkey.patch_all()
import gevent
import gevent.pool
import sys
import socket

LOOKUP_TIMEOUT = 10
PARALELLISM = 10

# DBL only lists hostnames. Spamhaus doesn't want you to query it for IPs,
# so they return a false positive for each IP address.
HOST_LOOKUP_ONLY = set([
    'dbl.spamhaus.org',
])

DNS_BLS = set([
    'b.barracudacentral.org',
    'cbl.abuseat.org',
    'http.dnsbl.sorbs.net',
    'misc.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'web.dnsbl.sorbs.net',
    'dnsbl-1.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'sbl.spamhaus.org',
    'zen.spamhaus.org',
    'dbl.spamhaus.org',
    'psbl.surriel.com',
    'dnsbl.njabl.org',
    'rbl.spamlab.com',
    'ircbl.ahbl.org',
    'noptr.spamrats.com',
    'cbl.anti-spam.org.cn',
    'dnsbl.inps.de',
    'httpbl.abuse.ch',
    'korea.services.net',
    'virus.rbl.jp',
    'wormrbl.imp.ch',
    'rbl.suresupport.com',
    'ips.backscatterer.org',
    'opm.tornevall.org',
    'multi.surbl.org',
    'tor.dan.me.uk',
    'relays.mail-abuse.org',
    'rbl-plus.mail-abuse.org',
    'access.redhawk.org',
    'rbl.interserver.net',
    'bogons.cymru.com',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'dul.dnsbl.sorbs.net',
    'smtp.dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'zombie.dnsbl.sorbs.net',
    'dnsbl-2.uceprotect.net',
    'pbl.spamhaus.org',
    'xbl.spamhaus.org',
    'bl.spamcannibal.org',
    'ubl.unsubscore.com',
    'combined.njabl.org',
    'dnsbl.ahbl.org',
    'dyna.spamrats.com',
    'spam.spamrats.com',
    'cdl.anti-spam.org.cn',
    'drone.abuse.ch',
    'dul.ru',
    'short.rbl.jp',
    'spamrbl.imp.ch',
    'virbl.bit.nl',
    'dsn.rfc-ignorant.org',
    'dsn.rfc-ignorant.org',
    'netblock.pedantic.org',
    'ix.dnsbl.manitu.net',
    'rbl.efnetrbl.org',
    'blackholes.mail-abuse.org',
    'dnsbl.dronebl.org',
    'db.wpbl.info',
    'query.senderbase.org',
    'bl.emailbasura.org',
    'combined.rbl.msrbl.net',
    'multi.uribl.com',
    'black.uribl.com',
    'cblless.anti-spam.org.cn',
    'cblplus.anti-spam.org.cn',
    'blackholes.five-ten-sg.com',
    'sorbs.dnsbl.net.au',
    'rmst.dnsbl.net.au',
    'dnsbl.kempt.net',
    'blacklist.woody.ch',
    'rot.blackhole.cantv.net',
    'virus.rbl.msrbl.net',
    'phishing.rbl.msrbl.net',
    'images.rbl.msrbl.net',
    'spam.rbl.msrbl.net',
    'spamlist.or.kr',
    'dnsbl.abuse.ch',
    'bl.deadbeef.com',
    'ricn.dnsbl.net.au',
    'forbidden.icm.edu.pl',
    'probes.dnsbl.net.au',
    'ubl.lashback.com',
    'ksi.dnsbl.net.au',
    'uribl.swinog.ch',
    'bsb.spamlookup.net',
    'dob.sibl.support-intelligence.net',
    'url.rbl.jp',
    'dyndns.rbl.jp',
    'omrs.dnsbl.net.au',
    'osrs.dnsbl.net.au',
    'orvedb.aupads.org',
    'relays.nether.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'dialups.mail-abuse.org',
    'rdts.dnsbl.net.au',
    'duinv.aupads.org',
    'dynablock.sorbs.net',
    'residential.block.transip.nl',
    'dynip.rothen.com',
    'dul.blackhole.cantv.net',
    'mail.people.it',
    'blacklist.sci.kun.nl',
    'all.spamblock.unit.liu.se',
])


class Host:
    def __init__(self, hostname=None, addr=None):
        self.hostname = hostname
        self.addr = addr

    def inverse_addr(self):
        """
        IPs are listed backwards, e.g. IP 1.2.3.4 -> 4.3.2.1.pbl.spamhaus.org
        """
        if self.addr is None:
            return None
        addr_split = self.addr.split(".")
        addr_split.reverse()
        return ".".join(addr_split)


def lookup(host_rbl):
    """
    Looks up a host in blacklist, returns whether it exists.
    Expects a tuple of (host, rbl), where host again is a tuple, of any
    length. The first field of host is used for the lookup (i.e. hostname
    or inverse ip), and the last field is printed in warning messages.
    """
    host, rbl = host_rbl
    rblhost = host[0] + "." + rbl
    try:
        socket.gethostbyname(rblhost)
        sys.stderr.write("WARNING: %s found in spam blocklist %s!\n" % (host[-1], rbl))
        sys.stderr.flush()
        return True
    except socket.gaierror:
        return False


def lookup_parallel(hosts_rbls):
    pool = gevent.pool.Pool(size=PARALELLISM)
    in_rbl = False
    for result in pool.imap_unordered(lookup, hosts_rbls):
        in_rbl = in_rbl or result
    return in_rbl


def print_usage():
    sys.stderr.write("usage: %s <host.name or IP> [host2.name or IP] ...\n" % sys.argv[0])
    sys.stderr.flush()


def get_host_and_ip(host_or_ip):
        """
        Given a hostname or ip address, this returns a Host instance with
        hostname and ip. One of the Host fields may be None, if a lookup
        fails.
        """
        host = host_or_ip
        addr = None
        try:
            addr = socket.gethostbyname(host)
            if addr == host:
                # addr and host are the same ip address
                host = socket.gethostbyaddr(addr)[0]
        except socket.gaierror:
            # no addr for hostname
            return Host(hostname=host)
        except socket.herror:
            # no hostname for addr
            return Host(addr=addr)
        return Host(hostname=host, addr=addr)


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    socket.setdefaulttimeout(LOOKUP_TIMEOUT)
    hosts_rbls = []
    for hostname_or_ip in sys.argv[1:]:
        host = get_host_and_ip(hostname_or_ip)
        for rbl in DNS_BLS:
            if host.hostname is not None:
                hosts_rbls.append(((host.hostname,), rbl))
            if rbl not in HOST_LOOKUP_ONLY and host.addr is not None:
                hosts_rbls.append(((host.inverse_addr(), host.addr), rbl))

    in_rbl = lookup_parallel(hosts_rbls)
    if in_rbl:
        sys.exit(1)


if __name__ in "__main__":
    main()
