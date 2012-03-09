"""
Funtions for talking to the nameserver for queies and updates.
"""
import config
import errors
import log

import dns.resolver
import struct
from subprocess import Popen, PIPE

class Dns(object):
    """
    Interface to the DNS.
    """
    def __init__(self, server=None):
        if server is None:
            server = config.DEFAULTS['nameserver']
        self.server = server
        self._make_resolver()
        self._make_updater_args()

    def _make_resolver(self):
        """
        Creates a resolver for DNS lookups.
        """
        myresolver = dns.resolver.Resolver(configure=False)
        # We need EDNS0 to get larger responses (or we could use TCP)
        # Allow max UDP packets for DNS Messages (4096 bytes)
        myresolver.use_edns(True, 0, 4096)
        myresolver.nameservers = [self.server]
        self._resolver = myresolver

    def _make_updater_args(self):
        """
        Sets up the external update argument vector.
        """
        defaults = config.DEFAULTS
        self._update_args = [defaults['path_nsupdate']]
        if defaults['update_extra_args']:
            self._update_args.extend(defaults['update_extra_args'].split())
        if defaults['update_use_tsig']:
            self._update_args.append("-k")
            self._update_args.append(defaults['path_update_key'])

    def lookup(self, qname, rdtype):
        """
        Lookup a given domain name and rdtype in the local nameserver.

        Returns instance of a dns.resolver.Answer or ().
        """
        try:
            return self._resolver.query(qname, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return () 

    def update(self, updates, ttl=None):
        """
        Dynamically update the nameserver from a list/str of updates.
        """
        defaults = config.DEFAULTS
        if ttl is None:
            ttl = defaults['update_ttl']
        if isinstance(updates, basestring):
            data = updates
        else:
            data = '\n\n'.join(updates)
        update_server = defaults['update_server']
        inp = defaults['update_template'] % (update_server, ttl, data)
        if config.DEBUG:
            log.log("dns update: %s" % ' '.join(self._update_args))
            log.log("dns update: %s" % inp)
        try:
            process = Popen(self._update_args, stdin=PIPE, stdout=PIPE,
                stderr=PIPE)
            stdout, stderr = process.communicate(inp)
        except OSError, err:
            raise errors.PszDnsError('%s' % err)
        if process.returncode != 0:
            if 'SERVFAIL' in stderr:
                raise errors.PszDnsUpdateServfail(stderr)
            else:
                raise errors.PszDnsError(stderr)

    def assert_count(self, qname, rdtype, expected_number):
        """
        Counts rrsets of rdtype and raises exception if the count doesn't match
        the expected number.
        """
        
        rrset = self.lookup(qname, rdtype)
        got_number = len(rrset)
        if got_number != expected_number: 
            mesg = "Expected %d records, received %d"
            mesg %= (expected_number, got_number)
            raise errors.PszDnsCountError(mesg)

    def add_dnskey(self, dnskey):
        update = 'update add %s' % dnskey.dnsdata
        self.update(update)

    def delete_dnskey(self, dnskey):
        update = 'update delete %s' % dnskey.dnsdata
        self.update(update)
        
        
def keytag(dnskey):
    """
    Given a dns.rdtypes.ANY.DNSKEY, compute and return its keytag.
    
    See rfc2535 section 4.1.6 for details.
    """
    if dnskey.algorithm == 1:
        a = ord(dnskey.key[-3]) << 8
        b = ord(dnskey.key[-2])
        return a + b
    else:
        header = struct.pack("!HBB", dnskey.flags, dnskey.protocol,
                                dnskey.algorithm)
        key = header + dnskey.key
        ac = 0
        for i, value in enumerate(ord(x) for x in key):
            if i % 2:
                ac += value
            else:
                ac += (value << 8)
        ac += (ac >> 16) & 0xffff
        return ac & 0xffff
