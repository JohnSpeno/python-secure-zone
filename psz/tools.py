"""
The methods here are the high level psz functions for zone signing
and key rollovers.

Most are invoked from the cli module's main() method via command line tools.
"""

import cli
from config import USAGE_ZONE, DEFAULTS as defaults
import log
import named
import errors

import os
import datetime

def _cleanup(keys):
    """
    Delete a list of keys.
    """
    for key in keys:
        key.unlink()
        key.save()

def _fix_zone(zone):
    """
    Removes trailing periods from zone.
    """
    return zone.rstrip('.') 

def _check_permissions(zone):
    """
    Check that we have the permissions and programs needed to run.

    We naively require all permissions for all tools instead of 
    speciflying a specific set of required permissions.

    The Django settings need to have been initialized first so we can
    verify that the database settings work.
    """
    failures = []
    # Check that zone key directories exists and are writable
    zone_dir = os.path.join(defaults['path_zonedir'], zone)
    if not os.access(zone_dir, os.W_OK):
        failures.append("path_zonedir '%s' is not writable" % zone_dir)
    newkeydir = os.path.join(zone_dir, defaults['path_newkeydir'])
    if not os.access(newkeydir, os.W_OK):
        failures.append("path_newkeydir '%s' is not writable" % newkeydir)
    oldkeydir = os.path.join(zone_dir, defaults['path_oldkeydir'])
    if not os.access(oldkeydir, os.W_OK):
        failures.append("path_oldkeydir '%s' is not writable" % oldkeydir)

    # Check that keygen command is executable
    keygen = defaults['path_keygen']
    if not os.access(keygen, os.X_OK):
        failures.append("path_keygen '%s' is not executable" % keygen)

    # Check that nsupdate command is executable
    nsupdate = defaults['path_nsupdate']
    if not os.access(nsupdate, os.X_OK):
        failures.append("path_nsupdate '%s' is not executable" % nsupdate)

    if defaults['update_use_tsig']:
        # Check that required TSIG key file is readable 
        update_key = defaults['path_update_key']
        if not os.access(update_key, os.R_OK):
            failures.append("path_update_key '%s' is not readable" % update_key)
    
    # Check that we can access the random device
    devrandom = defaults['path_random']
    if not os.access(devrandom, os.R_OK):
        failures.append("path_random '%s' is not readable" % devrandom)

    try:
        from django.db import connection
        connection.cursor()
    except Exception, e:
        failures.append("database error: '%s'" % e)

    if failures:
        raise errors.PszConfigError(*failures)

def _setup_tools():
    """
    Common setup for various tools.
    """
    opts, args = cli.parse_args()
    try:
        zone = _fix_zone(args[0])
    except IndexError:
        log.error(USAGE_ZONE)
    _check_permissions(zone)

    # We have to wait until Django is configured to import our models
    import models
    globals()['models'] = models
    return opts, zone

def _add_keys_to_dns(keys, zone, nameserver):
    """
    Adds a set of keys to the DNS.
    """
    update = 'update add %s'
    updates = []
    for key in keys: 
        updates.append(update % key.dnsdata)
    try:
        nameserver.update(updates)
    except errors.PszDnsError, err:
        log.error("Dns update error: (%s)" % err)
    expected_num_keys = len(keys)
    nameserver.assert_count(zone, 'DNSKEY', expected_num_keys)

def securezone():
    """
    this tool does the initial zone signing and key setup in the dnssec DB.

    create ksk, zsk1 in keydir and zsk2 in newkeydir
    publish all three dnskey records.
    """
    opts, zone = _setup_tools()
    Dnskey = models.Dnskey 
    keys = Dnskey.objects.get_zone_keys(zone) 
    if keys.count():
        _show_zone_keystatus(zone, verbose=False)
        log.error("\n%s already has the above keys." % zone,
            "psz retrysecurezone might work for this zone.")

    nameserver = named.Dns()
    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    if dnskey_rrset:
        num_keys = len(dnskey_rrset)
        log.error("The zone %s already has %d DNSKEYs" % (zone, num_keys))

    newkeydir = defaults['path_newkeydir']
    key_dir = os.path.join(defaults['path_zonedir'], zone, newkeydir)
    try:
        os.chdir(key_dir)
    except OSError, err:
        log.error("chdir failed: %s" % err) 

    keys_made = []
    try:
        zsk2 = Dnskey.from_dnssec_keygen(zone)
    except errors.PszKeygenError, err:
        log.error("keygen failed making ZSK2 for zone %s. %s" % (zone, err))
    zsk2.save()
    keys_made.append(zsk2)

    zonedir = os.path.join(defaults['path_zonedir'], zone)
    try:
        zsk1 = Dnskey.from_dnssec_keygen(zone)
    except errors.PszKeygenError, err:
        _cleanup(keys_made)
        mesg = "keygen failed making ZSK1 for zone %s. %s" % (zone, err)
        log.error(mesg)
    zsk1.update('pre-active')
    keys_made.append(zsk1)

    try:
        zsk1.move(zonedir)
    except errors.PszError, err:
        _cleanup(keys_made)
        mesg = "Failed to move ZSK1: %s." % err
        log.error(mesg)

    try:
        ksk = Dnskey.from_dnssec_keygen(zone, keytype='KSK')
    except errors.PszKeygenError, err:
        _cleanup(keys_made)
        log.error("keygen failed making KSK for zone %s. %s" % (zone, err))
    ksk.update('pre-active')
    keys_made.append(ksk)

    try:
        ksk.move(zonedir)
    except errors.PszError, err:
        _cleanup(keys_made)
        log.error("Failed to move KSK: %s" % err)

    return _common_securezone(keys_made, zone, nameserver)

def retrysecurezone():
    """
    Attempts to sign a zone if keys already exist. 
    """
    opts, zone = _setup_tools()
    Dnskey = models.Dnskey 
    nameserver = named.Dns()
    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    keytags = [named.keytag(dnskey) for dnskey in dnskey_rrset]
    keys = Dnskey.objects.get_zone_keys(zone)
    num_keys = len(keys)
    if num_keys != 3:
        log.error("wrong number of keys.")
    num_pre = num_zsk = num_ksk = 0
    for key in keys:
        if key.status == 'pre-active':
            num_pre += 1
        if key.type == 'ZSK':
            num_zsk += 1
        elif key.type == 'KSK':
            num_ksk += 1
    if num_pre != 2:
        mesg = "wrong number of 'pre-active' keys. Need two, got %d"
        mesg %= num_pre
        log.error(mesg)
    if num_ksk != 1:
        log.error("wrong number of KSK keys. Need one, got %d." % num_ksk)
    if num_zsk != 2:
        log.error("wrong number of ZSK keys. Need two, got %d" % num_zsk)
    keys_to_add = []
    for key in keys:
        if not int(key.keytag) in keytags:
            keys_to_add.append(key)
    if not keys_to_add:
        log.error("All the keys are in the DNS already.")

    return _common_securezone(keys_to_add, zone, nameserver)

def _common_securezone(keys, zone, nameserver):
    """
    Operational steps that both securezone and retrysecurezone
    have in common.
    """
    rs = "\nUse 'retrysecure' command to try again with existing keys."
    try:
        _add_keys_to_dns(keys, zone, nameserver)
    except errors.PszDnsError, err:
        log.error("Dns update error: (%s)" % err, rs)
    except errors.PszDnsCountError, err:
        log.error(err, rs)
    
    for key in keys:
        if key.status == 'pre-active':
            key.update('active')
        else:
            key.update('published')

    mesg = "%s secured." % zone
    print mesg 
    models.LogMessage(zone=zone, message=mesg).save()
    log.log(mesg)
    return 0

def unsign():
    """
    Deletes a zone's DNSKEYs from the DNS and deletes the on disk keys.
    """
    opts, zone = _setup_tools()
    Dnskey = models.Dnskey 
    keys = Dnskey.objects.get_zone_keys(zone) 
    nameserver = named.Dns()

    retry_keys = []
    for key in keys:
        try:
            nameserver.delete_dnskey(key)
        except errors.PszDnsUpdateServfail:
            retry_keys.append(key)
            continue
        key.unlink()
        print "Deleted %s" % key

    for key in retry_keys:
        nameserver.delete_dnskey(key)
        key.unlink()
        print "Deleted %s" % key

    mesg = "%s has been unsigned." % zone
    print mesg 
    models.LogMessage(zone=zone, message=mesg).save()

def rollover_zsk_stage1():
    """
    Performs a stage 1 ZSK rollover for a zone.

    Makes old ZSK stop signing by moving it to old key directory.
    Makes new ZSK start signing by moving it to the zone directory.

    Does not change contents of the zone in the DNS.
    """
    opts, zone = _setup_tools()
    Dnskey = models.Dnskey 

    zone_dir = os.path.join(defaults['path_zonedir'], zone)
    oldkey_dir = os.path.join(zone_dir, defaults['path_oldkeydir'])

    try:
        newkey = Dnskey.objects.get(zone=zone, status='published', type='ZSK')
    except Dnskey.DoesNotExist, Dnskey.MultipleObjectsReturned:
        log.error("Unable to determine the published ZSK for %s" % zone)

    try:
        oldkey = Dnskey.objects.get(zone=zone, status='active', type='ZSK')
    except Dnskey.DoesNotExist, Dnskey.MultipleObjectsReturned:
        log.error("Unable to determine the active ZSK for %s" % zone)

    try:
        oldkey.move(oldkey_dir)
    except errors.PszError, err:
        log.error("Failed moving ZSK (keyid=%s): %s." % (oldkey.keytag, err))
    oldkey.update('rolled-stage1')

    try:
        newkey.move(zone_dir)
    except errors.PszError, err:
        log.error("Failed moving ZSK (keyid=%s): %s." % (newkey.keytag, err))
    newkey.update('active')

    s = "keyid=%s is still published but no longer signing RRsets."
    s %= oldkey.keytag
    emits = [
        "%s rollover_zsk_stage1 complete." % zone, 
        "keyid=%s is now signing this zone's RRsets." % newkey.keytag,
        s, 
    ]
    for emit in emits:
        log.log(emit)
        print emit
    models.LogMessage(zone=zone, message="did stage 1 ZSK rollover").save()
    return 0

def rollover_zsk_stage2():
    """
    Performs stage2 rollover of ZSK for a zone.

    Deletes the old ZSK from the DNS.
    Creates a new ZSK and adds it to the DNS.
    """
    opts, zone = _setup_tools() 
    Dnskey = models.Dnskey 

    nameserver = named.Dns()
    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    prev_num_dnskeys = len(dnskey_rrset)
    if not prev_num_dnskeys:
        log.error("There are no DNSKEYs in the DNS for %s" % zone)

    try:
        oldzsk = Dnskey.objects.get(zone=zone, status='rolled-stage1',
                                    type='ZSK')
    except Dnskey.DoesNotExist, Dnskey.MultipleObjectsReturned:
        log.error("Unable to determine old ZSK for %s" % zone)

    newkeydir = opts['path_newkeydir']
    key_dir = os.path.join(opts['path_zonedir'], zone, newkeydir)
    try:
        os.chdir(key_dir)
    except OSError, err:
        log.error("chdir failed: %s" % err) 

    try:
        newzsk = Dnskey.from_dnssec_keygen(zone)
    except errors.PszKeygenError, err:
        log.error("keygen failed making ZSK for zone %s. %s" % (zone, err))
    newzsk.save()

    try:
        nameserver.delete_dnskey(oldzsk)
    except errors.PszDnsError, err:
        # xxx retry
        newzsk.unlink()
        newzsk.save()
        msg = "named.update failed to delete old ZSK, keyid=%s"
        msg %= oldzsk.keytag
        log.error(msg)

    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    expected_num_dnskeys = prev_num_dnskeys - 1
    num_dnskeys = len(dnskey_rrset)
    if num_dnskeys != expected_num_dnskeys:
        # xxx retry
        msg = "Got %d DNSKEYs, expected %d after deleting keyid=%s"
        log.error(msg % (num_dnskeys, expected_num_dnskeys, oldzsk.keytag))

    oldzsk.update('expired')

    try:
        nameserver.add_dnskey(newzsk)
    except errors.PszDnsError, err:
        # XXX retry
        msg = "DNS update failed to add new ZSK, keyid=%s" % newzsk.keytag
        log.error(msg)
    
    expected_num_dnskeys = num_dnskeys 
    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    num_dnskeys = len(dnskey_rrset)
    if num_dnskeys != expected_num_dnskeys + 1:
        # XXX retry
        msg = "Got %d DNSKEYs, expected %d after adding keyid=%s"
        msg %= (num_dnskeys, expected_num_dnskeys, newzsk.keytag)
        log.error(msg)

    newzsk.update('published')

    emits = [
        "%s rollover_zsk_stage2 complete." % zone, 
        "keyid=%s created and published." % newzsk.keytag,
        "keyid=%s removed from the DNS and expired." % oldzsk.keytag,
    ]
    for emit in emits:
        log.log(emit)
        print emit
    models.LogMessage(zone=zone, message="did stage 2 ZSK rollover").save()
    return 0

def rollover_ksk_stage1():
    """
    Performs a stage 1 rollover of the KSK for a zone.

    Makes a new active KSK for the zone.
    Adds the new KSK to the DNS.
    """
    opts, zone = _setup_tools() 
    Dnskey = models.Dnskey 

    nameserver = named.Dns()
    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    prev_num_dnskeys = len(dnskey_rrset)
    if not prev_num_dnskeys:
        log.error("There are no DNSKEYs for %s" % zone)

    try:
        oldksk = Dnskey.objects.get(zone=zone, type='KSK', status='active')
    except Dnskey.DoesNotExist, Dnskey.MultipleObjectsReturned:
        log.error("Unable to determine old KSK for %s" % zone)
    
    newkeydir = opts['path_newkeydir']
    key_dir = os.path.join(opts['path_zonedir'], zone, newkeydir)
    try:
        os.chdir(key_dir)
    except OSError, err:
        log.error("chdir failed: %s" % err) 

    try:
        newksk = Dnskey.from_dnssec_keygen(zone, keytype='KSK')
    except errors.PszKeygenError, err:
        log.error("keygen failed making new KSK for zone %s. %s" % (zone, err))
   
    try:
        nameserver.add_dnskey(newksk)
    except errors.PszDnsError, err:
        # xxx retry
        msg = "Failed adding new KSK to DNS. %s" % err
        log.error(msg)
    
    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    expected_num_dnskeys = prev_num_dnskeys + 1
    num_dnskeys = len(dnskey_rrset)
    if num_dnskeys != expected_num_dnskeys:
        # xxx retry
        msg = "Got %d DNSKEYs, expected %d after adding new KSK keyid=%s"
        log.error(msg % (num_dnskeys, expected_num_dnskeys, newksk.keytag))

    oldksk.update('rolled-stage1')
    newksk.update('active')

    msg = "keyid=%s was created, published and is signing the DNSKEY RRset."
    msg %= newksk.keytag
    emits = [ "%s rollover_ksk_stage1 complete" % zone, msg ]
    for emit in emits:
        log.log(emit)
        print emit
    models.LogMessage(zone=zone, message="did stage1 KSK rollover").save()
    return 0

def rollover_ksk_stage2():
    """
    Performs a stage 2 rollover of the KSK for a zone.

    Makes old KSK stop signing by moving it to the old key directory.
    And removes the old KSK from the DNS.
    """
    opts, zone = _setup_tools() 
    Dnskey = models.Dnskey 

    try:
        oldksk = Dnskey.objects.get(zone=zone, status='rolled-stage1',
                                    type='KSK')
    except Dnskey.DoesNotExist, Dnskey.MultipleObjectsReturned:
        log.error("Unable to determine the old KSK for %s" % zone)

    nameserver = named.Dns()
    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    prev_num_dnskeys = len(dnskey_rrset)
    if not prev_num_dnskeys:
        log.error("There are no DNSKEYs for %s" % zone)

    try:
        nameserver.delete_dnskey(oldksk)
    except errors.PszDnsError, err:
        # XXX retry
        log.error("failed to delete old KSK keyid=%s from DNS" % oldksk.keytag)

    dnskey_rrset = nameserver.lookup(zone, 'DNSKEY')
    expected_num_dnskeys = prev_num_dnskeys - 1
    num_dnskeys = len(dnskey_rrset)
    if num_dnskeys != expected_num_dnskeys:
        # XXX retry?
        msg = "Got %d DNSKEYs, expected %d after deleting KSK keyid=%s"
        log.error(msg % (num_dnskeys, expected_num_dnskeys, oldksk.keytag))

    zone_dir = os.path.join(defaults['path_zonedir'], zone)
    oldkey_dir = os.path.join(zone_dir, defaults['path_oldkeydir'])
    try:
        oldksk.move(oldkey_dir)
    except errors.PszError, err:
        log.error("Failed to move old KSK: %s." % err)

    oldksk.update('expired')
   
    emits = [
        "%s rollover_ksk_stage2 complete." % zone,
        "keyid=%s was deleted the DNSKEY RRset." % oldksk.keytag,
    ]
    for emit in emits:
        log.log(emit)
        print emit
    models.LogMessage(zone=zone, message="did stage2 KSK rollover").save()
    return 0

def _show_zone_keystatus(zone, verbose=False):
    """
    Display the status of keys for a zone.
    """
    if verbose:
        fmt = "%s %s (%s key, %d bits) has been %s since"
    else:
        fmt = "%s %s (%s key, %d bits) is %s"
    Dnskey = models.Dnskey 
    zones = {}
    zonekeys = Dnskey.objects.get_zone_keys(zone)
    for key in zonekeys:
        zones.setdefault(key.zone, []).append(key)
    if not zones:
        s = "%s either has no keys in the DNS or doesn't exist."
        print s % zone
        return
    zone_list = zones.keys()
    zone_list.sort()
    now = datetime.datetime.now()
    for zone in zone_list:
        zones[zone].sort()
        print '\n', zone
        print '-' * len(zone)
        for key in zones[zone]:
            s = fmt % (key.type, key.keytag, key.algorithm,
                        key.size, key.status)
            print s,
            if not verbose:
                print
                continue
            updated = key.updated
            age = now - updated
            days = age.days
            if days:
                print '%d days ago' % days
            else:
                print 'earlier today' 

def key_status():
    """
    Displays a report of active keys.
    """
    opts, args = cli.keystatus_parse_args()
    import models
    globals()['models'] = models
    verbose = opts['verbose']
    if not args:
        _show_zone_keystatus(None, verbose)
    else:
        for zone in args:
            zone = _fix_zone(zone)
            _show_zone_keystatus(zone, verbose)
    return 0

def showconfig():
    opts, args = cli.parse_args()
    cf = opts.pop('configfile')
    print "# Configuration file: %s\n" % cf
    keys = opts.keys()
    keys.sort()
    for key in keys:
        print '%s=%r' % (key, opts[key])
    return 0

def createdb():
    """
    Create the database tables needed by psz.
    """
    from django.core.management.commands import syncdb
    opts, args = cli.parse_args()
    cmd = syncdb.Command()
    cmd.handle_noargs()
    from django.db import connection
    cursor = connection.cursor()
    # Django can't created indexes on MySQL text fields
    # http://code.djangoproject.com/ticket/2495
    # so we have to do it by hand
    if DEFAULTS['db_engine'] == 'mysql': 
        # XXX we should construct the table name dynamically
        cursor.execute('create index zone_index on psz_dnskey (zone(255))')
        cursor.execute('create index zone_index on psz_logmessage (zone(255))')
    return 0

def shell():
    """
    Run an interactive Python shell configured for our models. 
    """
    from django.core.management.commands import shell
    opts, args = cli.parse_args()
    cmd = shell.Command()
    cmd.handle_noargs()
    return 0

# Make a few aliases for commands
config = showconfig
secure = securezone
unsecure = unsign
retry = retrysecure = retrysecurezone
roll_zsk_stage1 = rollover_zsk_stage1
roll_zsk_stage2 = rollover_zsk_stage2
roll_ksk_stage1 = rollover_ksk_stage1
roll_ksk_stage2 = rollover_ksk_stage2
status = key_status 
