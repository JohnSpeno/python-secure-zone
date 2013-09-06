"""
Default options for pysecurezone.

Those in the DEFAULTS dict are overridable via the config file and a few of
them can be overridden by command line switches.

All the other variables are not configurable except by editing this file.
"""

# Default Settings
DEFAULTS = {
    # Database engine name
    'db_engine' : '',

    # Database host
    'db_host' : '',

    # Database port
    'db_port' : '',

    # Database name
    'db_name' : '',

    # Database user name
    'db_user' : '',

    # Database password
    'db_pass' : '',

    # Path to dnssec-keygen command
    'path_keygen'  : '/usr/local/sbin/dnssec-keygen',

    # Path to nsupdate command
    'path_nsupdate' : '/usr/local/bin/nsupdate',

    # Path of random device
    'path_random'     : '/dev/urandom',

    # Base path for zone directories.
    'path_zonedir'      : '/usr/local/etc/bind/zones',

    # Name of directory holding new keys in each zone directory
    'path_newkeydir'     : 'newkeys',

    # Name of directory holding old keys in each zone directory
    'path_oldkeydir'     : 'oldkeys',

    # Path to keyfile for TSIG of dynamic updates
    'path_update_key' : '',

    'zsk_algorithm'  : 'RSASHA1',
    'zsk_keysize'    : '1024',
    'ksk_algorithm'  : 'RSASHA1',
    'ksk_keysize'    : '2048',

    # Address of nameserver for DNS lookups
    'nameserver'     : '127.0.0.1',

    # Address of nameserver receiving dynamic updates
    'update_server'  : '127.0.0.1',

    # TTL for DNS records added via dynamic update
    'update_ttl'     : 7200,

    # string format of update to send to nsupdate command
    'update_template' : 'server %s\nttl %d\n%s\nsend\n',

    # Whitepsace seperated list of additional args for nsupdate
    'update_extra_args' : '-v',

    # Does our dynamic update need to use TSIG?
    'update_use_tsig' : True,
}

# These things aren't defaults so much.
try:
    import os
    USER = os.getlogin()
    del os
except:
    USER = '<unknown user>'

USAGE_ZONE = "You must supply the name of the DNS zone as the last argument.\n"

DEBUG = False

DEFAULT_CONFIG_PATH = '/usr/local/etc/psz.conf'

# These values are from RFC 4034, section A.1.  DNSSEC Algorithm Types
# http://www.iana.org/assignments/dns-sec-alg-numbers/
KEY_ALGORITHMS = {
    'RSAMD5': '001',
    'DH': '002',
    'DSA': '003',
    'ECC': '004',
    'RSASHA1': '005',
    'DSANSEC3SHA1': '006',
    'RSASHA1NSEC3SHA1': '007',
    'RSASHA256': '008',
    'RSASHA512': '010',
    'ECCGOST': '012',
    'ECDSAP256SHA256': '013',
    'ECDSAP384SHA384': '014',
}

COMMAND_HELP = """Python Secure Zone

commands:

  status             shows the status of DNSKEYs in a zone
  secure             initializes DNSSEC for a zone
  roll_zsk_stage1    perform the 1st stage rollover of zone's ZSK
  roll_zsk_stage2    perform the 2nd stage rollover of zone's ZSK
  roll_ksk_stage1    perform the 1st stage rollover of zone's KSK
  roll_ksk_stage2    perform the 2nd stage rollover of zone's KSK
  unsign             removes all DNSKEYs from a zone

  showconfig         display psz's configuration settings
  createdb           creates database tables for the first time
  shell              Runs interactive Python shell configured for psz
  listkeys           Displays all keyfiles for active keys
"""
