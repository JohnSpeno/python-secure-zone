#!/usr/bin/env python

import sys
import dns.name
import dns.resolver
import hashlib
import psz.named

def is_ksk(dnskey):
    return dnskey.flags == 257

def main(args):
    try:
        zone = args[1] 
    except IndexError:
        print "give me a zone"
        return

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['127.0.0.1']
    answers = resolver.query(zone, 'DNSKEY', tcp=True)
    ksk = filter(is_ksk, answers)
    if ksk:
        ksk = ksk[0]
    else:
        print "no KSK found"
        return

    owner = dns.name.from_text(zone, origin=dns.name.root)

    digest = owner.to_wire() + ksk.to_digestable()
    sha1 = hashlib.sha1(digest).hexdigest().upper()
    sha256 = hashlib.sha256(digest).hexdigest().upper()

    keytag = psz.named.keytag(ksk)

    print "%s's KSK has a keytag of %s\n" % (zone, keytag)
    print "SHA-1 of the key is:"
    print sha1
    print "\nSHA-256 of the key is:"
    print sha256

if __name__ == '__main__':
    main(sys.argv)
