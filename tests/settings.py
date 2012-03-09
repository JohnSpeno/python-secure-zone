import os

this_dir = os.path.realpath(os.path.dirname(__file__))
DATABASE_NAME = this_dir + '/.testing.db'
DATABASE_ENGINE = 'sqlite3'
INSTALLED_APPS=('psz',)
