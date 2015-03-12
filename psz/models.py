"""
psz's data model.

The class Dnskey is the important one. It handles the creation and operation of
dnssec key files.

BaseDnskey provides the persistance layer via Django's ORM.

LogMessage is hardly used and should probably just go away.
"""

from django.db import models
from django.db.models import Manager
from datetime import datetime
import os
import sys

import config
import keygen
from errors import PszError

KEY_TYPES = (
    ('ZSK', 'Zone signing key'),
    ('KSK', 'Key signing key')
)

KEY_ALGOS = [(k, v) for k, v in config.KEY_ALGORITHMS.iteritems()]

KEY_STATUSES = (
    ('new', 'a newly created key pair. key not in DNS'),
    ('pre-active', 'key pair in place to sign, but not in DNS'),
    ('published', 'key in DNS but not signing'),
    ('active', 'key in DNS and signing records'),
    ('rolled-stage1', 'key in DNS, ZSK not signing. KSK signing'),
    ('expired', 'key not in DNS. not signing.'),
    ('deleted', 'key pair files have been deleted'),
)


class DnskeyManager(Manager):
    """
    Provides convenience methods for Dnskey objects.
    """
    def get_zone_keys(self, zone=None):
        """
        Returns the non expired keys for a zone or for all zones if
        no zone is specified.
        """
        qs = self.get_query_set().exclude(status__in=['expired', 'deleted'])
        if zone:
            qs = qs.filter(zone=zone)
        return qs


class BaseDnskey(models.Model):
    """
    A BaseDnskey object. It just handles the ORM bits of a Dnskey.
    It's abstract, so no tables will be created for this model.
    """
    algorithm = models.CharField(max_length=128, choices=KEY_ALGOS)
    keytag = models.CharField(max_length=128, db_index=True)
    zone = models.TextField(db_index=True)
    type = models.CharField(max_length=32, choices=KEY_TYPES)
    size = models.IntegerField()
    status = models.CharField(
        max_length=128, choices=KEY_STATUSES,
        default='new'
    )
    updated = models.DateTimeField(default=datetime.now)

    class Meta:
        abstract = True

    objects = DnskeyManager()

    def __cmp__(self, other):
        return cmp(self.type, other.type)

    def __unicode__(self):
        return "%s %s %s (%s %s bits)" % (
            self.zone, self.type, self.keytag, self.algorithm, self.size
            )

_KEY_LOCATIONS = {
    'new': config.DEFAULTS['path_newkeydir'],
    'published': config.DEFAULTS['path_newkeydir'],
    'pre-active': '',
    'active': '',
    'ksk+rolled-stage1': '',
    'zsk+rolled-stage1': config.DEFAULTS['path_oldkeydir'],
    'expired': config.DEFAULTS['path_oldkeydir'],
    'deleted': None,
}


def _key_file_path(zone, keytype, keystatus):
    """
    Returns the directory where a key's files should be located
    or None if it can't be determined.
    """
    try:
        subdir = _KEY_LOCATIONS[keystatus]
    except KeyError:
        k = '%s+%s' % (keytype.lower(), keystatus)
        subdir = _KEY_LOCATIONS.get(k, None)
    if subdir is None:
        return None
    return str(os.path.join(config.DEFAULTS['path_zonedir'], zone, subdir))


class Dnskey(BaseDnskey):
    """
    A Dnskey that exists on the filesystem as a keypair.
    """
    def __init__(self, *args, **kwargs):
        super(Dnskey, self).__init__(*args, **kwargs)
        self._dnsdata = None
        self._directory = None
        self._keyname = None
        self._path_public = None
        self._path_private = None

    @property
    def dnsdata(self):
        """Returns the public key portion of the DNSKEY's rdata."""
        if self._dnsdata is not None:
            return self._dnsdata
        if self.path_public is None:
            return None
        try:
            self._dnsdata = open(self.path_public).read()[:-1]
        except IOError:
            pass
        return self._dnsdata

    @dnsdata.setter
    def dnsdata(self, value):
        self._dnsdata = value

    @property
    def keyname(self):
        if self._keyname is None:
            if self.algorithm and self.zone and self.keytag:
                algonum = config.KEY_ALGORITHMS[self.algorithm]
                keyname = 'K%s.+%s+%s' % (self.zone, algonum, self.keytag)
                self._keyname = str(keyname)
        return self._keyname

    @keyname.setter
    def keyname(self, value):
        self._keyname = value

    @property
    def directory(self):
        if not self.zone:
            return None
        if self._directory is None:
            self._directory = _key_file_path(self.zone, self.type, self.status)
        return self._directory

    @directory.setter
    def directory(self, value):
        self._directory = value

    @property
    def path_private(self):
        if self.directory is None:
            return None
        if self._path_private is None:
            if self.keyname:
                filename = '%s.private' % self.keyname
                self._path_private = os.path.join(self.directory, filename)
        return self._path_private

    @property
    def path_public(self):
        if self.directory is None:
            return None
        if self._path_public is None:
            if self.keyname:
                filename = '%s.key' % self.keyname
                self._path_public = os.path.join(self.directory, filename)
        return self._path_public

    def move(self, destination):
        """
        Move key's files to destination.
        """
        public_file = '%s.key' % self.keyname
        new_path_public = os.path.join(destination, public_file)
        try:
            os.rename(self.path_public, new_path_public)
        except OSError, e:
            raise PszError('%s' % e)
        self._path_public = new_path_public

        private_file = '%s.private' % self.keyname
        new_path_private = os.path.join(destination, private_file)
        try:
            os.rename(self.path_private, new_path_private)
        except OSError, e:
            raise PszError('%s' % e)
        self._path_private = new_path_private
        self.directory = destination

    def unlink(self):
        """
        Unlinks a key's public and private files.
        """
        if self.path_public and self.path_private:
            try:
                os.unlink(self.path_public)
            except OSError, e:
                print >>sys.stderr, "%s" % e
            try:
                os.unlink(self.path_private)
            except OSError, e:
                print >>sys.stderr, "%s" % e
            self.update('deleted')

    def update(self, status):
        """
        Saves Dnskey with new status.
        """
        if status == self.status:
            return
        self.status = status
        self.updated = datetime.now()
        self.save()

    @classmethod
    def from_dnssec_keygen(cls, zone, keytype='ZSK', algname=None, size=None):
        """Create key pair on disk and returns Dnskey instance
        The instance isn't saved in the ORM by default.
        XXX move this to keygen directory?
        """
        if algname is None:
            algname = config.DEFAULTS[keytype.lower() + '_algorithm']
        if size is None:
            size = config.DEFAULTS[keytype.lower() + '_keysize']
        keyname, dnsdata = keygen.create_key(zone, algname, size, keytype)
        nameparts = keyname.split('+')
        keytag = nameparts[2]
        inst = cls(
            algorithm=algname, keytag=keytag,
            zone=zone, type=keytype, size=size,
        )
        inst.dnsdata = dnsdata
        inst.keyname = keyname
        inst.directory = os.getcwd()
        return inst


class LogMessage(models.Model):
    zone = models.TextField(db_index=True)
    user = models.CharField(max_length=32, default=config.USER)
    timestamp = models.DateTimeField(default=datetime.now)
    message = models.TextField()
