# vim: set fileencoding=utf-8 ai et sts=4 sw=4 tw=0:
# # -*- coding: <utf-8> -*-
## Userdir-LDAP exception classes 
## © 2009 Stephen Gran <sgran@debian.org>
## © 2009 Mark Hymers <mhy@debian.org>
"""
These classes implement the necessary exceptions in the userdir-ldap namespace
"""

class UDError(Exception):
    """
    Base class for exceptions in ud-ldap.
    """
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message
    
    def __str__(self):
        return "UDError: %s" % self.message

__all__ = ['UDError']

UDERRORS = {
    "UDPasswdError": """Exception raised for authentication errors.""",
    "UDFormatError": """Exception raised for data format errors.""",
    "UDExecuteError": """Exception raised for subprocess execution errors.""",
    "UDNotAllowedError": """Exception raised for attempts to modify off-limits or disabled entries.""",
}

def construct_udld_exception(name, description):
    """Generator function for userdir-ldap exceptions"""

    class Error(UDError):
        """meta class for user-ldap exceptions"""
        __doc__ = description

    setattr(Error, "__name__", name)
    return Error

for key in UDERRORS.keys():
    globals()[key] = construct_udld_exception(key, UDERRORS[key])
    __all__ += [key]

