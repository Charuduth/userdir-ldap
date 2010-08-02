
class Account:
    def __init__(self, user):
        searchresult = lc.search_s(BaseDn,ldap.SCOPE_SUBTREE, 'uid=%s'%(user))
        if len(searchresult) < 1:
            sys.stderr.write("No such user: %s\n"%(user))
            return
        elif len(searchresult) > 1:
            sys.stderr.write("More than one hit when getting %s\n"%(user))
            return

        self.dn, self.attributes = searchresult[0]


    def has_mail(self):
        if 'mailDisableMessage' in self.attributes:
            return False
        return True

    # not locked locked,  just reset to something invalid like {crypt}*SSLRESET* is still active
    def pw_active(self):
        if self.attributes['userPassword'][0] == '{crypt}*LK*':
            return False
        return True

    # not expired
    def shadow_active(self):
        if 'shadowExpire' in self.attributes and \
            int(self.attributes['shadowExpire'][0]) < (time.time() / 3600 / 24):
            return False
        return True

    def numkeys(self):
        if 'keyFingerPrint' in self.attributes:
            return len(self.attributes['keyFingerPrint'])
        return 0

    def account_status(self):
        if 'accountStatus' in self.attributes:
            return self.attributes['accountStatus'][0]
        return 'active'


    def verbose_status(self):
        status = []
        status.append('mail: %s'  %(['disabled', 'active'][ self.has_mail() ]))
        status.append('pw: %s'    %(['locked', 'active'][ self.pw_active() ]))
        status.append('shadow: %s'%(['expired', 'active'][ self.shadow_active() ]))
        status.append('keys: %d'  %( self.numkeys() ))
        status.append('status: %s'%( self.account_status() ))

        return '(%s)'%(', '.join(status))

    def get_dn(self):
        return self.dn

# vim:set et:
# vim:set ts=4:
# vim:set shiftwidth=4:
