-- Creates tables used by dnskey programs to keep track of Secure DNS keys

use dnssec;

create table dnskeys (  
    id int auto_increment PRIMARY KEY,

    -- the domain name of the zone this key is for
    zone text,

    -- This is the keytag or keyid of the key. We only ever allow a key once
    -- per zone.
    keytag varchar(128),

    -- either ZSK or KSK.
    type varchar(32),

    -- the alorithm name used to make the key, e.g. RSASHA1
    algorithm varchar(128),

    -- the number of bits in the key
    size int,

    -- status can be one of [new, published, expired,
    status varchar(128),

    index(keytag),
    index(zone(256))
);

create table log (
    id int auto_increment PRIMARY KEY,
    user varchar(128) NOT NULL,
    action_time datetime not null,
    zone text NOT NULL,
    keytag varchar(128),
    type varchar(32),
    old_status varchar(128) not NULL,
    new_status varchar(128) not NULL,
    change_message text NOT NULL,
    index(keytag),
    index(zone(256)),
    index(action_time)
);
