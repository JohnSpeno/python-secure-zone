# install dnssec module
# install command-line tools
# man pages?

from distutils.core import setup

packages = ['psz']

scripts = [
    'bin/psz',
    'bin/siggraph',
    'bin/sync-dnssec-keys',
]

setup(name='psz', version='0.3', packages=packages, scripts=scripts)
