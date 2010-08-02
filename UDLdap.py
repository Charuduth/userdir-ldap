import ldap
import time
import userdir_ldap

class Account:
    array_values = ['keyFingerPrint', 'mailWhitelist', 'mailRBL', 'mailRHSBL', 'supplementaryGid', 'sshRSAAuthKey', 'sudoPassword']
    int_values = ['shadowExpire', 'gidNumber']
    defaults = {
                 'accountStatus': 'active',
                 'keyFingerPrint': []
               }

    @staticmethod
    def from_search(ldap_connection, base, user):
        searchresult = ldap_connection.search_s(base, ldap.SCOPE_SUBTREE, 'uid=%s'%(user))
        if len(searchresult) < 1:
            sys.stderr.write("No such user: %s\n"%(user))
            return
        elif len(searchresult) > 1:
            sys.stderr.write("More than one hit when getting %s\n"%(user))
            return
        else:
            return Account(searchresult[0][0], searchresult[0][1])

    def __init__(self, dn, attributes):
        self.dn = dn
        self.attributes = attributes

    def __getitem__(self, key):
        if key in self.attributes:
            if key in self.array_values:
                return self.attributes[key]

            if not len(self.attributes[key]) == 1:
                raise ValueError, 'non-array value has not exactly one value'

            if key in self.int_values:
                return int(self.attributes[key][0])
            else:
                return self.attributes[key][0]
        elif key in self.defaults:
            return self.defaults[key]
        else:
            raise IndexError

    def __contains__(self, key):
        return key in self.attributes

    def has_mail(self):
        if 'mailDisableMessage' in self.attributes:
            return False
        return True

    # not locked locked,  just reset to something invalid like {crypt}*SSLRESET* is still active
    def pw_active(self):
        if self['userPassword'] == '{crypt}*LK*':
            return False
        if self['userPassword'].startswith("!"):
            return False
        return True

    # not expired
    def shadow_active(self):
        if 'shadowExpire' in self and \
            self['shadowExpire'] < (time.time() / 3600 / 24):
            return False
        return True

    def numkeys(self):
        return len(self['keyFingerPrint'])

    def is_active_user(self):
        return self['accountStatus'] == 'active' and self.numkeys() != 0

    def latitude_dec(self, anonymized=False):
        return userdir_ldap.DecDegree(self['latitude'], anonymized)
    def longitude_dec(self, anonymized=False):
        return userdir_ldap.DecDegree(self['longitude'], anonymized)

    def verbose_status(self):
        status = []
        status.append('mail: %s'  %(['disabled', 'active'][ self.has_mail() ]))
        status.append('pw: %s'    %(['locked', 'active'][ self.pw_active() ]))
        status.append('shadow: %s'%(['expired', 'active'][ self.shadow_active() ]))
        status.append('keys: %d'  %( self.numkeys() ))
        status.append('status: %s'%( self['accountStatus'] ))

        return '(%s)'%(', '.join(status))

    def get_dn(self):
        return self.dn

# vim:set et:
# vim:set ts=4:
# vim:set shiftwidth=4:
