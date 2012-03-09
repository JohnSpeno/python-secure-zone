"""
Exceptions for psz.

You can stringify these exceptions to get a message about the error type and
whatver extra string arguments that were passed in when the object was created.
"""

class PszError(Exception):
    _msg = ''
    def __str__(self):
        s = []
        if self._msg: 
            s.append(self._msg)
        s.extend(self.args)
        return '\n'.join(s)

class PszConfigError(PszError):
    _msg = 'There was a problem with your configuration. Check the following:\n'

class PszKeygenError(PszError):
    _msg = 'Keygen error: '

class PszDnsError(PszError):
    _meg = 'Dns Error: '

class PszDnsCountError(PszDnsError):
    pass

class PszDnsUpdateServfail(PszDnsError):
    _msg = 'Dns SERVFAIL Error'
