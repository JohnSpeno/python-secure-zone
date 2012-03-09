import MySQLdb as mysql
from django.conf import settings

def main():
    create_dnskeys()
    #create_logs()

def create_dnskeys():
    db = mysql.Connection(user='dnssec', passwd='swineherd', db='dnssec') 
    cursor = db.cursor()
    q = """
        SELECT keytag, status, size, algorithm, type, zone from dnskeys
    """
    cursor.execute(q)
    for row in cursor.fetchall():
        keytag, status, size, algorithm, type, zone = row
        inst = Dnskey(
            keytag=keytag, status=status, zone=zone,
            size=size, algorithm=algorithm, type=type
        )
        q2 = """
        SELECT action_time from log where zone = %s
        AND keytag = %s
        AND type = %s
        and new_status = %s
        """
        cursor.execute(q2, (zone, keytag, type, status))
        update = cursor.fetchone()[0] 
        print zone, keytag, type, update
        inst.updated = update
        inst.save()

def create_logs():
    db = mysql.Connection(user='dnssec', passwd='swineherd', db='dnssec') 
    cursor = db.cursor()
    q = """
        SELECT zone, keytag, user, old_status, new_status, action_time,
        change_message
        FROM log
    """ 
    cursor.execute(q)
    for row in cursor.fetchall():
        zone, keytag, user, old_status, new_status, timestamp, message = row
        inst = LogMessage(
            zone=zone, keytag=keytag, user=user,
            old_status=old_status, new_status=new_status,
            timestamp=timestamp, message=message
        )
        inst.save()
                    
if __name__ == '__main__':
    settings.configure(
        DATABASE_ENGINE='mysql',
        DATABASE_NAME='psztest',
        DATABASE_USER='psztest',
        DATABASE_PASSWORD='psztest',
        DATABASE_HOST='',
        DATABASE_PORT='',
    )
    from psz.models import Dnskey, LogMessage
    main()
