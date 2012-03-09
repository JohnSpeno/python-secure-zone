"""
Logging routines dnssec tools.

Emits to syslog.

This module needs refactoring.
"""

import logging
import logging.handlers
import config
import sys
import os

if os.path.exists("/dev/log"):
    # Linux
    SYSLOG_PATH = "/dev/log"
elif os.path.exists("/var/run/syslog"):
    # MacOS X
    SYSLOG_PATH = "/var/run/syslog"
else:
    # logging will try via UDP connection to localhost
    SYSLOG_PATH = None

LOGGER = logging.getLogger("dnssec")
LOGGER.setLevel(logging.DEBUG)
FACILITY = logging.handlers.SysLogHandler.LOG_DAEMON 

SYSLOG_H = logging.handlers.SysLogHandler(address=SYSLOG_PATH,
    facility=FACILITY)
FORMATTER = logging.Formatter("%(message)s")
SYSLOG_H.setFormatter(FORMATTER)
LOGGER.addHandler(SYSLOG_H)

def log(msg):
    """
    Logs to syslog with username and caller.
    """
    func_name = LOGGER.findCaller()[2]
    LOGGER.info('%s: %s: %s' % (func_name, config.USER, msg))
   
def error(*msgs):
    """
    Logs error to syslog and stderr and bails.
    """
    msg = '\n'.join(str(m) for m in msgs)
    sys.stderr.write("%s\n" % msg)
    log(msg)
    sys.exit(1)

if __name__ == '__main__':
    log("testing from psz")
