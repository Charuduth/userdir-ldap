import ldap
import time
import datetime
import userdir_ldap
import sys

class Account:
    array_values = ['objectClass', 'keyFingerPrint', 'mailWhitelist', 'mailRBL',
                    'mailRHSBL', 'supplementaryGid', 'sshRSAAuthKey',
                    'sudoPassword', 'dnsZoneEntry', 'allowedHost']
    int_values = ['shadowExpire', 'gidNumber', 'uidNumber']
    defaults = {
                 'accountStatus': 'active',
                 'keyFingerPrint': []
               }

    @staticmethod
    def from_search(ldap_connection, base, user):
        searchresult = ldap_connection.search_s(base, ldap.SCOPE_SUBTREE, 'uid=%s'%(user))
        if len(searchresult) < 1:
            raise IndexError, "No such user: %s\n"%(user)
        elif len(searchresult) > 1:
            raise IndexError, "More than one hit when getting %s\n"%(user)
        else:
            return Account(searchresult[0][0], searchresult[0][1])

    def __init__(self, dn, attributes):
        self.dn = dn
        self.attributes = attributes
        self.cache = {}

    def __getitem__(self, key):
        if key in self.cache:
            return self.cache[key]

        if key in self.attributes:
            if key in self.array_values:
                self.cache[key] = self.attributes[key]
            elif not len(self.attributes[key]) == 1:
                raise ValueError, 'non-array value has not exactly one value'
            elif key in self.int_values:
                self.cache[key] = int(self.attributes[key][0])
            else:
                self.cache[key] = self.attributes[key][0]
        elif key in self.defaults:
            self.cache[key] = self.defaults[key]
        else:
            raise IndexError, "No such key: %s (dn: %s)"%(key, self.dn)

        return self.cache[key]

    def __contains__(self, key):
        return key in self.attributes

    def has_mail(self):
        if 'mailDisableMessage' in self.attributes:
            return False
        return True

    # not locked locked,  just reset to something invalid like {crypt}*SSLRESET* is still active
    def pw_active(self):
        if not 'userPassword' in self:
            return False
        if self['userPassword'].upper() == '{CRYPT}*LK*':
            return False
        if self['userPassword'].upper().startswith("{CRYPT}!"):
            return False
        return True

    def get_password(self):
        p = self['userPassword']
        if not p.upper().startswith('{CRYPT}') or len(p) > 50:
            return p
        else:
            return p[7:]

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

    def is_guest_account(self):
        return 'supplementaryGid' in self and 'guest' in self['supplementaryGid']

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

    def delete_mailforward(self):
        del self.attributes['emailForward']

    def get_dn(self):
        return self.dn

    def email_address(self):
        mailbox = "<%s@%s>" % (self['uid'], userdir_ldap.EmailAppend)
        tokens = []
        if 'cn' in self: tokens.append(self['cn'])
        if 'sn' in self: tokens.append(self['sn'])
        tokens.append(mailbox)
        return ' '.join(tokens)

    def is_allowed_by_hostacl(self, host):
        if not 'allowedHost' in self: return False
        if host in self['allowedHost']: return True
        # or maybe it's a date limited ACL
        for entry in self['allowedHost']:
            list = entry.split(None,1)
            if len(list) == 1: continue
            (h, expire) = list
            if host != h: continue
            try:
                parsed = datetime.datetime.strptime(expire, '%Y%m%d')
            except ValueError:
                print >>sys.stderr, "Cannot parse expiry date in '%s' in hostACL entry for %s."%(entry, self['uid'])
                return False
            return parsed >= datetime.datetime.now()
        return False


# vim:set et:
# vim:set ts=4:
# vim:set shiftwidth=4:
