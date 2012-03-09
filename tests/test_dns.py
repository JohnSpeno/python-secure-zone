from psz import named

def setup_module():
    pass

def teardown():
    pass

def test_dns_defaults():
    dns = named.Dns()
    assert dns.server == '127.0.0.1'

def test_dns_resolver_server():
    dns = named.Dns(server='ns1')
    assert 'ns1' in dns._resolver.nameservers

def test_dns_update():
    dns = named.Dns()
    assert dns.update is not None
