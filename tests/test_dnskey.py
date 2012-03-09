from django.conf import settings
from psz import config
from psz.models import Dnskey
from psz import  named
import dns.rrset
import os

TEST_ZONE_NAME = 'psz.test.zone.co.uk'

def setup_module():
    config.DEFAULTS['path_zonedir'] = '/tmp'
    os.chdir('/tmp')
    if not os.path.exists(TEST_ZONE_NAME):
        os.mkdir(TEST_ZONE_NAME)
        os.mkdir(os.path.join(TEST_ZONE_NAME, 'newkeys'))
        os.mkdir(os.path.join(TEST_ZONE_NAME, 'oldkeys'))
    os.chdir(os.path.join(TEST_ZONE_NAME, 'newkeys'))

def teardown():
    keys = Dnskey.objects.all()
    for key in keys:
        key.unlink()
        key.delete()

def test_key_empty_dnskey():
    key = Dnskey()
    s = str(key)
    assert key.dnsdata is None

def test_key_generate_key():
    key = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME)
    assert key.keytag is not ''
    keynamebit = 'K' + TEST_ZONE_NAME
    assert keynamebit in key.path_public
    assert keynamebit in key.path_private
    assert key.directory == os.getcwd()
    assert key.dnsdata is not None
    assert TEST_ZONE_NAME in key.dnsdata
    path = os.path.join(config.DEFAULTS['path_zonedir'],
        TEST_ZONE_NAME, 'newkeys')
    assert os.path.exists(key.path_public)
    assert os.path.exists(key.path_private)
    key.save()

def test_key_dnskey_read():
    key = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME, keytype='ksk')
    dns = key.dnsdata
    key.save()
    keyid = key.id
    key = Dnskey.objects.get(pk=keyid)
    assert key.dnsdata == dns

def test_key_unlink():
    key = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME)
    path = os.path.join(config.DEFAULTS['path_zonedir'],
        TEST_ZONE_NAME, 'newkeys')
    assert os.path.exists(key.path_public)
    assert os.path.exists(key.path_private)
    key.unlink()
    assert not os.path.exists(key.path_public)
    assert not os.path.exists(key.path_private)

def test_key_move():
    key = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME)
    key.save()
    path = os.path.join(config.DEFAULTS['path_zonedir'],
        TEST_ZONE_NAME, 'newkeys')
    assert os.path.exists(key.path_public)
    assert os.path.exists(key.path_private)
    newpath = os.path.join(config.DEFAULTS['path_zonedir'],
        TEST_ZONE_NAME, 'oldkeys')
    key.move(newpath)
    key.status = 'expired'
    key.save()
    public_file = '%s.key' % key.keyname
    new_path_public = os.path.join(newpath, public_file)
    assert os.path.exists(os.path.join(newpath, key.path_public))
    assert key.path_public == new_path_public
    assert os.path.exists(os.path.join(newpath, key.path_private))
    private_file = '%s.private' % key.keyname
    new_path_private = os.path.join(newpath, private_file)
    assert key.path_private == new_path_private

def test_key_get_zone_keys():
    count = Dnskey.objects.get_zone_keys(TEST_ZONE_NAME).count()
    key1 = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME)
    key1.save()
    key2 = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME)
    key2.save()
    keys = Dnskey.objects.get_zone_keys(TEST_ZONE_NAME)
    assert keys.count() == count + 2

def test_key_directory():
    key = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME)
    key.save()
    keyid = key.id
    oldpath = os.path.realpath(key.directory)
    keyfromdb = Dnskey.objects.get(pk=keyid)
    newpath = os.path.realpath(keyfromdb.directory)
    assert newpath == oldpath

def test_named_keygen():
    key = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME)
    key.save()
    dnstext = key.dnsdata.split(' ', 3)[-1]
    dnskeys = dns.rrset.from_text(TEST_ZONE_NAME, 300, 'in', 'dnskey', dnstext)
    assert int(key.keytag) == named.keytag(dnskeys[0]) 
    key2 = Dnskey.from_dnssec_keygen(TEST_ZONE_NAME, algname='RSAMD5')
    key2.save()
    dnstext = key2.dnsdata.split(' ', 3)[-1]
    dnskeys = dns.rrset.from_text(TEST_ZONE_NAME, 300, 'in', 'dnskey', dnstext)
    assert int(key2.keytag) == named.keytag(dnskeys[0]) 
