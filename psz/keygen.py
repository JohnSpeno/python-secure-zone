"""
The module has one function:

    create_key - Creates DNSKEYs
"""
from config import DEFAULTS as defaults
from errors import PszKeygenError

import subprocess

def create_key(zone, algorithm, keysize, keytype):
    """
    Create DNSKEY using dnssec-keygen with specified parameters
    """
    cmd_args = [defaults['path_keygen'], "-r", defaults['path_random'],
           "-a", algorithm, "-b", keysize, "-n", "ZONE"]
    if keytype == 'KSK':
        cmd_args += ["-f", "KSK"]
    cmd_args.append(zone)
    try:
        process = subprocess.Popen(cmd_args, stdout=subprocess.PIPE)
        output = process.communicate()[0]
    except OSError, e: 
        raise PszKeygenError('%s' % e)
    returncode = process.returncode
    if returncode != 0:
        msg = ' '.join(cmd_args)
        raise PszKeygenError("Command failed: %s, rc=%d" % (msg, returncode))
    keyname = output[:-1]
    nameparts = keyname.split('+')
    keytag = nameparts[2]
    try:
        dnsdata = open("%s.key" % keyname).read()[:-1]
    except OSError, e:
        raise PszKeygenError('%s' % e)

    return keyname, dnsdata
