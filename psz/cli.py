"""
Module containing command-line tool functions for psz.

"""
import config
import log
import errors

import os
import sys
from optparse import OptionParser
from configobj import ConfigObj, ConfigObjError
from django.conf import settings

def _configure_django(opts):
    """
    Configure Django's ORM settings which are needed before we import our
    models. The settings need to be initialized before we can import out
    modles.
    """
    settings.configure(
        DATABASE_ENGINE=opts['db_engine'],
        DATABASE_NAME=opts['db_name'],
        DATABASE_USER=opts['db_user'],
        DATABASE_PASSWORD=opts['db_pass'],
        DATABASE_HOST=opts['db_host'],
        DATABASE_PORT=opts['db_port'],
        INSTALLED_APPS=('psz',)
    )

def _get_config_from_file(config_path):
    """
    Read the config file. psz requires that a config file exists. 
    """
    try:
        cfg = ConfigObj(infile=config_path, file_error=True,
            unrepr=True, interpolation=False) 
    except (IOError, ConfigObjError), err:
        msg = "Error reading %s: %s" % (config_path, err)
        log.error(msg)
    return cfg

def parse_args():
    """
    Parse CLI args for most of psz's tools. 

    """
    usage = "usage: %prog [options] zone"
    parser = OptionParser(usage=usage)

    defaults = config.DEFAULTS
    key_algs = config.KEY_ALGORITHMS.keys()

    parser.add_option("-c", dest="configfile",
        default=config.DEFAULT_CONFIG_PATH,
        help="Specify path to config file")
    parser.add_option("--zsk_algorithm", choices=key_algs,
        dest="zsk_algorithm",
        help="Specifies the algorithm used for new ZSK keys")
    parser.add_option("--zsk_keysize", dest="zsk_keysize", 
        help="Specifies the number of bits in new ZSK keys")
    parser.add_option("--ksk_algorithm", choices=key_algs,
        dest="ksk_algorithm",
        help="Specifies the algorithm used for new KSK keys")
    parser.add_option("--ksk_keysize", dest="ksk_keysize",
        help="Specifies the number of bits in new ZSK keys")
    parser.add_option("-d", dest="debug", action="store_true", default=False,
        help="turns on extra debugging output and logging")
    
    # Parse args to get a config file arg if any
    options, args = parser.parse_args()

    cfg = _get_config_from_file(options.configfile)
    defaults.update(cfg)

    parser.set_defaults(**defaults)
    options, args = parser.parse_args()

    # now update the config.defaults with any from command-line args
    defaults.update(vars(options))

    if options.debug:
        config.DEBUG = True

    _configure_django(defaults)

    return defaults, args

def keystatus_parse_args():
    """
    Parse CLI args for psz's keystatus tool.
    """
    usage = "usage: %prog [options] [zone...]"
    parser = OptionParser(usage=usage)

    parser.add_option("-c", dest="configfile",
        default=config.DEFAULT_CONFIG_PATH,
        help="Specify path to config file")
    parser.add_option("-v", dest="verbose", action="store_true", default=False,
        help="shows more verbose output")
    options, args = parser.parse_args()

    defaults = config.DEFAULTS
    cfg = _get_config_from_file(options.configfile)
    defaults.update(cfg)

    defaults['verbose'] = options.verbose
    _configure_django(defaults)
    return defaults, args

def main():
    """
    When 'psz toolname' is invoked from the command line, this function
    is the first to run. It then invokes the proper tool.
    """
    import tools
    try:
        prog, sys.argv = sys.argv[1], sys.argv[1:]
    except IndexError:
        sys.stderr.write(config.COMMAND_HELP)
        sys.exit(1)
    try:
        tool = getattr(tools, prog)
    except AttributeError:
        sys.stderr.write(config.COMMAND_HELP)
        sys.exit(1)
    try:
        rc = tool()
    except errors.PszConfigError, err:
        log.error(err)
    sys.exit(rc)

if __name__ == '__main__':
    main() 
