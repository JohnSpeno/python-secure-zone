This project is a command line tool to manange DNSSEC keys via dynamic DNS updates.

To install
----------

    python setup.py install

    edit psz.conf to match local configuration

    (as root) cp psz.conf /usr/local/etc/psz.conf
    (as root) chown named /usr/local/etc/psz.conf
    (as root) chmod 700 /usr/local/etc/psz.conf

Requires
--------

* Django 1.1
* MySQLdb-1.2.1p2 or newer
* dnspython
* bind 9.6
* configobj - http://www.voidspace.org.uk/python/configobj.html

Usage
-----

    % psz help
    Python Secure Zone

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

Instructions
------------

1. Configure your nameserver. :-)
2. Configure your local database.
3. `psz createdb`
4. `psz secure myzone.com` 
5. `pzs status` to show your work
