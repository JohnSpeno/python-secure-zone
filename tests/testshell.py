#!/usr/bin/env python -i

import os
from psz.config import DEFAULTS as defaults
os.environ['DJANGO_SETTINGS_MODULE']='settings'
from psz.models import Dnskey
defaults['path_zonedir'] = '/tmp'
TEST_ZONE_NAME = 'psz.test.zone.co.uk'
keynamebit = 'K' + TEST_ZONE_NAME
key = Dnskey.from_dnssec_keygen(zone='psz.test.zone.co.uk')

