# Some routines and configuration that are used by the ldap progams
import termios, TERMIOS, re, string, imp, ldap, sys, whrandom, crypt;

try:
   File = open("/etc/userdir-ldap/userdir-ldap.conf");
except:
   File = open("userdir-ldap.conf");
ConfModule = imp.load_source("userdir_config","/etc/userdir-ldap.conf",File);
File.close();

BaseDn = ConfModule.basedn;
BaseDn = ConfModule.basedn;
LDAPServer = ConfModule.ldaphost;
EmailAppend = ConfModule.emailappend;
AdminUser = ConfModule.adminuser;
GenerateDir = ConfModule.generatedir;
GenerateConf = ConfModule.generateconf;
DefaultGID = ConfModule.defaultgid;
TemplatesDir = ConfModule.templatesdir;
PassDir = ConfModule.passdir;

# This is a list of common last-name prefixes
LastNamesPre = {"van": None, "le": None, "de": None, "di": None};
   
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
   import termios, TERMIOS, sys;
   fd = sys.stdin.fileno();
   old = termios.tcgetattr(fd);
   new = termios.tcgetattr(fd);
   new[3] = new[3] & ~TERMIOS.ECHO;          # lflags
   try:
      termios.tcsetattr(fd, TERMIOS.TCSADRAIN, new);
      passwd = raw_input(prompt);
   finally:
      termios.tcsetattr(fd, TERMIOS.TCSADRAIN, old);
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
   if len(Words) > 2:
      while len(Words[2]) == 2 and Words[2][1] == '.':
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
   for i in range(0,10):
      Password = Password + SaltVals[ord(Rand.read(1)[0]) % len(SaltVals)];
   return Password;

# Compute the MD5 crypted version of the given password
def HashPass(Password):
   # Hash it telling glibc to use the MD5 algorithm - if you dont have
   # glibc then just change Salt = "$1$" to Salt = "";
   SaltVals = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/.";
   Salt  = "$1$";
   for x in range(0,10):
      Salt = Salt + SaltVals[whrandom.randint(0,len(SaltVals)-1)];
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
def DecDegree(Attr,Type,Anon=0):
  Parts = re.match('[+-]?(\d*)\\.?(\d*)?',GetAttr(Attr,Type)).groups();
  Val = string.atof(GetAttr(Attr,Type));

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
