# Some routines and configuration that are used by the ldap progams
import termios, re, string, imp, ldap, sys, whrandom, crypt, rfc822;
import userdir_gpg

try:
   File = open("/etc/userdir-ldap/userdir-ldap.conf");
except:
   File = open("userdir-ldap.conf");
ConfModule = imp.load_source("userdir_config","/etc/userdir-ldap.conf",File);
File.close();

# Cheap hack
BaseDn = ConfModule.basedn;
HostBaseDn = ConfModule.hostbasedn;
LDAPServer = ConfModule.ldaphost;
EmailAppend = ConfModule.emailappend;
AdminUser = ConfModule.adminuser;
GenerateDir = ConfModule.generatedir;
GenerateConf = ConfModule.generateconf;
DefaultGID = ConfModule.defaultgid;
TemplatesDir = ConfModule.templatesdir;
PassDir = ConfModule.passdir;
Ech_ErrorLog = ConfModule.ech_errorlog;
Ech_MainLog = ConfModule.ech_mainlog;

# Break up the keyring list
userdir_gpg.SetKeyrings(string.split(ConfModule.keyrings,":"));

# This is a list of common last-name prefixes
LastNamesPre = {"van": None, "von": None, "le": None, "de": None, "di": None};

# SSH Key splitting. The result is:
# (options,size,modulous,exponent,comment)
SSHAuthSplit = re.compile('^(.* )?(\d+) (\d+) (\d+) ?(.+)$');
SSH2AuthSplit = re.compile('^(.* )?ssh-(dss|rsa) ([a-zA-Z0-9=/+]+) ?(.+)$');
#'^([^\d](?:[^ "]+(?:".*")?)*)? ?(\d+) (\d+) (\d+) (.+)$');

AddressSplit = re.compile("(.*).*<([^@]*)@([^>]*)>");

# Safely get an attribute from a tuple representing a dn and an attribute
# list. It returns the first attribute if there are multi.
def GetAttr(DnRecord,Attribute,Default = ""):
   try:
      return DnRecord[1][Attribute][0];
   except IndexError:
      return Default;
   except KeyError:
      return Default;
   return Default;

# Return a printable email address from the attributes.
def EmailAddress(DnRecord):
   cn = GetAttr(DnRecord,"cn");
   sn = GetAttr(DnRecord,"sn");
   uid = GetAttr(DnRecord,"uid");
   if cn == "" and sn == "":
      return "<" + uid + "@" + EmailAppend + ">";
   return cn + " " + sn + " <" + uid + "@" + EmailAppend + ">"

# Show a dump like ldapsearch
def PrettyShow(DnRecord):
   Result = "";
   List = DnRecord[1].keys();
   List.sort();
   for x in List:
      Rec = DnRecord[1][x];
      for i in Rec:
         Result = Result + "%s: %s\n" % (x,i);
   return Result[:-1];

# Function to prompt for a password 
def getpass(prompt = "Password: "):
   import termios, sys;
   fd = sys.stdin.fileno();
   old = termios.tcgetattr(fd);
   new = termios.tcgetattr(fd);
   new[3] = new[3] & ~termios.ECHO;          # lflags
   try:
      termios.tcsetattr(fd, termios.TCSADRAIN, new);
      passwd = raw_input(prompt);
   finally:
      termios.tcsetattr(fd, termios.TCSADRAIN, old);
   print;
   return passwd;

# Split up a name into multiple components. This tries to best guess how
# to split up a name
def NameSplit(Name):
   Words = re.split(" ",string.strip(Name));

   # Insert an empty middle name
   if (len(Words) == 2):
      Words.insert(1,"");
   if (len(Words) < 2):
      Words.append("");

   # Put a dot after any 1 letter words, must be an initial
   for x in range(0,len(Words)):
      if len(Words[x]) == 1:
         Words[x] = Words[x] + '.';

   # If a word starts with a -, ( or [ we assume it marks the start of some
   # Non-name information and remove the remainder of the string
   for x in range(0,len(Words)):
      if len(Words[x]) != 0 and (Words[x][0] == '-' or \
          Words[x][0] == '(' or Words[x][0] == '['):
         Words = Words[0:x];
         break;
	 
   # Merge any of the middle initials
   while len(Words) > 2 and len(Words[2]) == 2 and Words[2][1] == '.':
      Words[1] = Words[1] +  Words[2];
      del Words[2];

   while len(Words) < 2:
      Words.append('');
   
   # Merge any of the last name prefixes into one big last name
   while LastNamesPre.has_key(string.lower(Words[-2])):
      Words[-1] = Words[-2] + " " + Words[-1];
      del Words[-2];

   # Fix up a missing middle name after lastname globbing
   if (len(Words) == 2):
      Words.insert(1,"");

   # If the name is multi-word then we glob them all into the last name and
   # do not worry about a middle name
   if (len(Words) > 3):
      Words[2] = string.join(Words[1:]);
      Words[1] = "";

   return (string.strip(Words[0]),string.strip(Words[1]),string.strip(Words[2]));

# Compute a random password using /dev/urandom
def GenPass():   
   # Generate a 10 character random string
   SaltVals = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.";
   Rand = open("/dev/urandom");
   Password = "";
   for i in range(0,15):
      Password = Password + SaltVals[ord(Rand.read(1)[0]) % len(SaltVals)];
   return Password;

# Compute the MD5 crypted version of the given password
def HashPass(Password):
   # Hash it telling glibc to use the MD5 algorithm - if you dont have
   # glibc then just change Salt = "$1$" to Salt = "";
   SaltVals = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/.";
   Salt  = "$1$";
   Rand = open("/dev/urandom");
   for x in range(0,10):
      Salt = Salt + SaltVals[ord(Rand.read(1)[0]) % len(SaltVals)];
   Pass = crypt.crypt(Password,Salt);
   if len(Pass) < 14:
      raise "Password Error", "MD5 password hashing failed, not changing the password!";
   return Pass;

# Sync with the server, we count the number of async requests that are pending
# and make sure result has been called that number of times
def FlushOutstanding(l,Outstanding,Fast=0):
   # Sync with the remote end
   if Fast == 0:
      print "Waiting for",Outstanding,"requests:",
   while (Outstanding > 0):
      try:
         if Fast == 0 or Outstanding > 50:
            sys.stdout.write(".",);
            sys.stdout.flush();
            if (l.result(ldap.RES_ANY,1) != (None,None)):
               Outstanding = Outstanding - 1;
         else:
            if (l.result(ldap.RES_ANY,1,0) != (None,None)):
               Outstanding = Outstanding - 1;
	    else:
               break;
      except ldap.TYPE_OR_VALUE_EXISTS:
         Outstanding = Outstanding - 1;
      except ldap.NO_SUCH_ATTRIBUTE:
         Outstanding = Outstanding - 1;
      except ldap.NO_SUCH_OBJECT:
         Outstanding = Outstanding - 1;
   if Fast == 0:
      print;
   return Outstanding;

# Convert a lat/long attribute into Decimal degrees
def DecDegree(Posn,Anon=0):
  Parts = re.match('[-+]?(\d*)\\.?(\d*)',Posn).groups();
  Val = string.atof(Posn);

  if (abs(Val) >= 1806060.0):
     raise ValueError,"Too Big";

  # Val is in DGMS
  if abs(Val) >= 18060.0 or len(Parts[0]) > 5:
     Val = Val/100.0;
     Secs = Val - long(Val);
     Val = long(Val)/100.0;
     Min = Val - long(Val);
     Val = long(Val) + (Min*100.0 + Secs*100.0/60.0)/60.0;

  # Val is in DGM
  elif abs(Val) >= 180 or len(Parts[0]) > 3:
     Val = Val/100.0;
     Min = Val - long(Val);
     Val = long(Val) + Min*100.0/60.0;
     
  if Anon != 0:
      Str = "%3.2f"%(Val);
  else:
      Str = str(Val);
  if Val >= 0:
     return "+" + Str;
  return Str;

def FormatSSH2Auth(Str):
   Match = SSH2AuthSplit.match(Str);
   if Match == None:
      return "<unknown format>";
   G = Match.groups();

   if G[0] == None:
      return "ssh-%s %s..%s %s"%(G[1],G[2][:8],G[2][-8:],G[3]);
   return "%s ssh-%s %s..%s %s"%(G[0],G[1],G[2][:8],G[2][-8:],G[3]);

def FormatSSHAuth(Str):
   Match = SSHAuthSplit.match(Str);
   if Match == None:
      return FormatSSH2Auth(Str);
   G = Match.groups();

   # No options
   if G[0] == None:
      return "%s %s %s..%s %s"%(G[1],G[2],G[3][:8],G[3][-8:],G[4]);
   return "%s %s %s %s..%s %s"%(G[0],G[1],G[2],G[3][:8],G[3][-8:],G[4]);

def FormatPGPKey(Str):
   Res = "";

   # PGP 2.x Print
   if (len(Str) == 32):
      I = 0;
      while (I < len(Str)):
         if I+2 == 32/2:
            Res = "%s %s%s "%(Res,Str[I],Str[I+1]);
         else:
            Res = "%s%s%s "%(Res,Str[I],Str[I+1]);
         I = I + 2;
   elif (len(Str) == 40):
      # OpenPGP Print
      I = 0;
      while (I < len(Str)):
         if I+4 == 40/2:
            Res = "%s %s%s%s%s "%(Res,Str[I],Str[I+1],Str[I+2],Str[I+3]);
         else:
            Res = "%s%s%s%s%s "%(Res,Str[I],Str[I+1],Str[I+2],Str[I+3]);
         I = I + 4;
   else:
      Res = Str;
   return string.strip(Res);

# Take an email address and split it into 3 parts, (Name,UID,Domain)
def SplitEmail(Addr):
   # Is not an email address at all
   if string.find(Addr,'@') == -1:
      return (Addr,"","");
  
   Res1 = rfc822.AddrlistClass(Addr).getaddress();
   if len(Res1) != 1:
      return ("","",Addr);
   Res1 = Res1[0];
   if Res1[1] == None:
      return (Res1[0],"","");

   # If there is no @ then the address was not parsed well. Try the alternate
   # Parsing scheme. This is particularly important when scanning PGP keys.
   Res2 = string.split(Res1[1],"@");
   if len(Res2) != 2:
      Match = AddressSplit.match(Addr);
      if Match == None:
         return ("","",Addr);
      return Match.groups();

   return (Res1[0],Res2[0],Res2[1]);

# Convert the PGP name string to a uid value. The return is a tuple of
# (uid,[message strings]). UnknownMpa is a hash from email to uid that 
# overrides normal searching.
def GetUID(l,Name,UnknownMap = {}):
   # Crack up the email address into a best guess first/middle/last name
   (cn,mn,sn) = NameSplit(re.sub('["]','',Name[0]))
   
   # Brackets anger the ldap searcher
   cn = re.sub('[(")]','?',cn);
   sn = re.sub('[(")]','?',sn);

   # First check the unknown map for the email address
   if UnknownMap.has_key(Name[1] + '@' + Name[2]):
      Stat = "unknown map hit for "+str(Name);
      return (UnknownMap[Name[1] + '@' + Name[2]],[Stat]);

   # Then the cruft component (ie there was no email address to match)
   if UnknownMap.has_key(Name[2]):
      Stat = "unknown map hit for"+str(Name);
      return (UnknownMap[Name[2]],[Stat]);

   # Then the name component (another ie there was no email address to match)
   if UnknownMap.has_key(Name[0]):
      Stat = "unknown map hit for"+str(Name);
      return (UnknownMap[Name[0]],[Stat]);
  
   # Search for a possible first/last name hit
   try:
      Attrs = l.search_s(BaseDn,ldap.SCOPE_ONELEVEL,"(&(cn=%s)(sn=%s))"%(cn,sn),["uid"]);
   except ldap.FILTER_ERROR:
      Stat = "Filter failure: (&(cn=%s)(sn=%s))"%(cn,sn);
      return (None,[Stat]);

   # Try matching on the email address
   if (len(Attrs) != 1):
      try:
         Attrs = l.search_s(BaseDn,ldap.SCOPE_ONELEVEL,"emailforward=%s"%(Name[2]),["uid"]);
      except ldap.FILTER_ERROR:
	 pass;

   # Hmm, more than one/no return
   if (len(Attrs) != 1):
      # Key claims a local address
      if Name[2] == EmailAppend:

         # Pull out the record for the claimed user
         Attrs = l.search_s(BaseDn,ldap.SCOPE_ONELEVEL,"(uid=%s)"%(Name[1]),["uid","sn","cn"]);

         # We require the UID surname to be someplace in the key name, this
         # deals with special purpose keys like 'James Troup (Alternate Debian key)'
	 # Some people put their names backwards on their key too.. check that as well
         if len(Attrs) == 1 and \
            (string.find(string.lower(sn),string.lower(Attrs[0][1]["sn"][0])) != -1 or \
            string.find(string.lower(cn),string.lower(Attrs[0][1]["sn"][0])) != -1):
            Stat = EmailAppend+" hit for "+str(Name);
            return (Name[1],[Stat]);

      # Attempt to give some best guess suggestions for use in editing the
      # override file.
      Attrs = l.search_s(BaseDn,ldap.SCOPE_ONELEVEL,"(sn~=%s)"%(sn),["uid","sn","cn"]);

      Stat = [];
      if len(Attrs) != 0:
         Stat = ["None for %s"%(str(Name))];
      for x in Attrs:
         Stat.append("But might be: %s %s <%s@debian.org>"%(x[1]["cn"][0],x[1]["sn"][0],x[1]["uid"][0]));
      return (None,Stat);	 
   else:
      return (Attrs[0][1]["uid"][0],None);

   return (None,None);

