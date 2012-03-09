#!/bin/sh
export DJANGO_SETTINGS_MODULE=settings

if [ ! -f .testing.db ] ; then
    echo "Setting up the PSZ database..."
    python -c 'from django.core.management.commands import syncdb;syncdb.Command().handle_noargs()'
fi
nosetests -s
