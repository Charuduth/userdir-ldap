#   Copyright (c) 1999-2001  Jason Gunthorpe <jgg@debian.org>
#   Copyright (c) 2005       Joey Schulze <joey@infodrom.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# GPG issues -
#  - gpgm with a status FD being fed keymaterial and other interesting
#    things does nothing.. If it could ID the keys and stuff over the
#    status-fd I could decide what to do with them. I would also like it
#    to report which key it selected for encryption (also if there
#    were multi-matches..) Being able to detect a key-revoke cert would be
#    good too.
#  - I would like to be able to fetch the comment and version fields from the
#    packets so I can tell if a signature is made by pgp2 to enable the
#    pgp2 encrypting mode.

import sys, StringIO, os, tempfile, re;
import time, fcntl, anydbm
import email, email.message

from userdir_exceptions import *

# General GPG options
GPGPath = "gpg"
# "--load-extension","rsa",
GPGBasicOptions = [
   "--no-options",
   "--batch",
   "--no-default-keyring",
   "--secret-keyring", "/dev/null",
   "--always-trust"];
GPGKeyRings = [];
GPGSigOptions = ["--output","-"];
GPGSearchOptions = ["--dry-run","--with-colons","--fingerprint",\
                    "--fingerprint", "--fixed-list-mode"];
GPGEncryptOptions = ["--output","-","--quiet","--always-trust",\
                     "--armor","--encrypt"];
GPGEncryptPGP2Options = ["--set-filename","","--rfc1991",\
                         "--load-extension","idea",\
                         "--cipher-algo","idea"] + GPGEncryptOptions;

# Replay cutoff times in seconds
CleanCutOff = 7*24*60*60;
AgeCutOff = 4*24*60*60;
FutureCutOff = 3*24*60*60;

def ClearKeyrings():
   del GPGKeyRings[:]

# Set the keyrings, the input is a list of keyrings
def SetKeyrings(Rings):
   for x in Rings:
      GPGKeyRings.append("--keyring");
      GPGKeyRings.append(x);

# GetClearSig takes an un-seekable email message stream (mimetools.Message)
# and returns a standard PGP '---BEGIN PGP SIGNED MESSAGE---' bounded
# clear signed text.
# If this is fed to gpg/pgp it will verify the signature and spit out the
# signed text component. Email headers and PGP mime (RFC 2015) is understood
# but no effort is made to cull any information outside the PGP boundaries
# Please note that in the event of a mime decode the mime headers will be
# present in the signature text! The return result is a tuple, the first
# element is the text itself the second is a mime flag indicating if the
# result should be mime processed after sig checking.
#
# Paranoid will check the message text to make sure that all the plaintext is
# in fact signed (bounded by a PGP packet)
#
# lax_multipart: treat multipart bodies other than multipart/signed
# as one big plain text body
def GetClearSig(Msg, Paranoid = 0, lax_multipart = False):
   if not Msg.__class__ == email.message.Message:
      raise RuntimeError, "GetClearSign() not called with a email.message.Message"

   if Paranoid and lax_multipart:
      raise RuntimeError, "Paranoid and lax_multipart don't mix well"

   # See if this is a MIME encoded multipart signed message
   if Msg.is_multipart():
      if not Msg.get_content_type() == "multipart/signed":
         if lax_multipart:
            payloads = Msg.get_payload()
            msg = "\n".join(map( lambda p: p.get_payload(decode=True), payloads))
            return (msg, 0)
         raise UDFormatError, "Cannot handle multipart messages not of type multipart/signed";

      if Paranoid:
         if Msg.preamble is not None and Msg.preamble.strip() != "":
            raise UDFormatError,"Unsigned text in message (at start)";
         if Msg.epilogue is not None and Msg.epilogue.strip() != "":
            raise UDFormatError,"Unsigned text in message (at end)";

      payloads = Msg.get_payload()
      if len(payloads) != 2:
         raise UDFormatError, "multipart/signed message with number of payloads != 2";

      (Signed, Signature) = payloads

      if Signed.get_content_type() != "text/plain" and not lax_multipart:
         raise UDFormatError, "Invalid pgp/mime encoding for first part[wrong plaintext type]";
      if Signature.get_content_type() != "application/pgp-signature":
         raise UDFormatError, "Invalid pgp/mime encoding for second part [wrong signature type]";

      # Append the PGP boundary header and the signature text to re-form the
      # original signed block [needs to convert to \r\n]
      Output = "-----BEGIN PGP SIGNED MESSAGE-----\r\n";
      # Semi-evil hack to get the proper hash type inserted in the message
      if Msg.get_param('micalg') != None:
          Output = Output + "Hash: MD5,SHA1,%s\r\n"%(Msg.get_param('micalg')[4:].upper())
      Output = Output + "\r\n";
      Output = Output + Signed.as_string().replace("\n-","\n- -") + "\n" + Signature.get_payload(decode=True)
      return (Output,1);
   else:
      if Paranoid == 0:
         # Just return the message body
         return (Msg.get_payload(decode=True), 0);

      Body = [];
      State = 1;
      for x in Msg.get_payload(decode=True).split('\n'):
          Body.append(x)

          if x == "":
             continue;

          # Leading up to the signature
          if State == 1:
             if x == "-----BEGIN PGP SIGNED MESSAGE-----":
                State = 2;
             else:
                raise UDFormatError,"Unsigned text in message (at start)";
             continue;

          # In the signature plain text
          if State == 2:
             if x == "-----BEGIN PGP SIGNATURE-----":
                State = 3;
             continue;

          # In the signature
          if State == 3:
             if x == "-----END PGP SIGNATURE-----":
                State = 4;
             continue;

          # Past the end
          if State == 4:
             raise UDFormatError,"Unsigned text in message (at end)";

      return ("\n".join(Body), 0);

# This opens GPG in 'write filter' mode. It takes Message and sends it
# to GPGs standard input, pipes the standard output to a temp file along
# with the status FD. The two tempfiles are passed to GPG by fd and are
# accessible from the filesystem for only a short period. Message may be
# None in which case GPGs stdin is closed directly after forking. This
# is best used for sig checking and encryption.
# The return result is a tuple (Exit,StatusFD,OutputFD), both fds are
# fully rewound and readable.
def GPGWriteFilter(Program,Options,Message):
   # Make sure the tmp files we open are unreadable, there is a short race
   # between when the temp file is opened and unlinked that some one else
   # could open it or hard link it. This is not important however as no
   # Secure data is fed through the temp files.
   OldMask = os.umask(0777);
   try:
      Output = tempfile.TemporaryFile("w+b");
      GPGText = tempfile.TemporaryFile("w+b");
      InPipe = os.pipe();
      InPipe = [InPipe[0],InPipe[1]];
   finally:
      os.umask(OldMask);

   try:
      # Fork off GPG in a horrible way, we redirect most of its FDs
      # Input comes from a pipe and its two outputs are spooled to unlinked
      # temp files (ie private)
      Child = os.fork();
      if Child == 0:
         try:
            os.dup2(InPipe[0],0);
            os.close(InPipe[1]);
            os.dup2(Output.fileno(),1);
            os.dup2(os.open("/dev/null",os.O_WRONLY),2);
            os.dup2(GPGText.fileno(),3);

            Args = [Program,"--status-fd","3"] + GPGBasicOptions + GPGKeyRings + Options
            os.execvp(Program,Args);
         finally:
            os._exit(100);

      # Get rid of the other end of the pipe
      os.close(InPipe[0])
      InPipe[0] = -1;

      # Send the message
      if Message != None:
         try:
            os.write(InPipe[1],Message);
         except:
           pass;
      os.close(InPipe[1]);
      InPipe[1] = -1;

      # Wait for GPG to finish
      Exit = os.waitpid(Child,0);

      # Create the result including the new readable file descriptors
      Result = (Exit,os.fdopen(os.dup(GPGText.fileno()),"r"), \
                os.fdopen(os.dup(Output.fileno()),"r"));
      Result[1].seek(0);
      Result[2].seek(0);

      Output.close();
      GPGText.close();
      return Result;
   finally:
      if InPipe[0] != -1:
         os.close(InPipe[0]);
      if InPipe[1] != -1:
         os.close(InPipe[1]);
      Output.close();
      GPGText.close();

# This takes a text passage, a destination and a flag indicating the
# compatibility to use and returns an encrypted message to the recipient.
# It is best if the recipient is specified using the hex key fingerprint
# of the target, ie 0x64BE1319CCF6D393BF87FF9358A6D4EE
def GPGEncrypt(Message,To,PGP2):
   Error = "KeyringError"
   # Encrypt using the PGP5 block encoding and with the PGP5 option set.
   # This will handle either RSA or DSA/DH asymetric keys.
   # In PGP2 compatible mode IDEA and rfc1991 encoding are used so that
   # PGP2 can read the result. RSA keys do not need PGP2 to be set, as GPG
   # can read a message encrypted with blowfish and RSA.
   searchkey = GPGKeySearch(To);
   if len(searchkey) == 0:
      raise Error, "No key found matching %s"%(To);
   elif len(searchkey) > 1:
      raise Error, "Multiple keys found matching %s"%(To);
   if searchkey[0][4].find("E") < 0:
      raise Error, "Key %s has no encryption capability - are all encryption subkeys expired or revoked?  Are there any encryption subkeys?"%(To);

   if PGP2 == 0:
      try:
         Res = None;
         Res = GPGWriteFilter(GPGPath,["-r",To]+GPGEncryptOptions,Message);
         if Res[0][1] != 0:
            return None;
         Text = Res[2].read();
         return Text;
      finally:
         if Res != None:
            Res[1].close();
            Res[2].close();
   else:
      # We have to call gpg with a filename or it will create a packet that
      # PGP2 cannot understand.
      TmpName = tempfile.mktemp();
      try:
         Res = None;
         MsgFile = open(TmpName,"wc");
         MsgFile.write(Message);
         MsgFile.close();
         Res = GPGWriteFilter(GPGPath,["-r",To]+GPGEncryptPGP2Options+[TmpName],None);
         if Res[0][1] != 0:
            return None;
         Text = Res[2].read();
         return Text;
      finally:
         try:
            os.unlink(TmpName);
         except:
            pass;
         if Res != None:
            Res[1].close();
            Res[2].close();

# Checks the signature of a standard PGP message, like that returned by
# GetClearSig. It returns a large tuple of the form:
#   (Why,(SigId,Date,KeyFinger),(KeyID,KeyFinger,Owner,Length,PGP2),Text);
# Where,
#  Why = None if checking was OK otherwise an error string.
#  SigID+Date represent something suitable for use in a replay cache. The
#             date is returned as the number of seconds since the UTC epoch.
#             The keyID is also in this tuple for easy use of the replay
#             cache
#  KeyID, KeyFinger and Owner represent the Key used to sign this message
#         PGP2 indicates if the message was created using PGP 2.x
#  Text is the full byte-for-byte signed text in a string
def GPGCheckSig(Message):
   Res = None;
   try:
      Res = GPGWriteFilter(GPGPath,GPGSigOptions,Message);
      Exit = Res[0];

      # Parse the GPG answer
      Strm = Res[1];
      GoodSig = 0;
      SigId = None;
      KeyFinger = None;
      KeyID = None;
      Owner = None;
      Date = None;
      Why = None;
      TagMap = {};
      while(1):
         # Grab and split up line
         Line = Strm.readline();
         if Line == "":
            break;
         Split = re.split("[ \n]",Line);
         if Split[0] != "[GNUPG:]":
            continue;

         # We only process the first occurance of any tag.
         if TagMap.has_key(Split[1]):
            continue;
         TagMap[Split[1]] = None;

         # Good signature response
         if Split[1] == "GOODSIG":
            # Just in case GPG returned a bad signal before this (bug?)
            if Why == None:
               GoodSig = 1;
            KeyID = Split[2];
            Owner = ' '.join(Split[3:])
            # If this message is signed with a subkey which has not yet
            # expired, GnuPG will say GOODSIG here, even if the primary
            # key already has expired.  This came up in discussion of
            # bug #489225.  GPGKeySearch only returns non-expired keys.
            Verify = GPGKeySearch(KeyID);
            if len(Verify) == 0:
               GoodSig = 0
               Why = "Key has expired (no unexpired key found in keyring matching %s)"%(KeyId);

         # Bad signature response
         if Split[1] == "BADSIG":
            GoodSig = 0;
            KeyID = Split[2];
            Why = "Verification of signature failed";

         # Bad signature response
         if Split[1] == "ERRSIG":
            GoodSig = 0;
            KeyID = Split[2];
            if len(Split) <= 7:
               Why = "GPG error, ERRSIG status tag is invalid";
            elif Split[7] == '9':
               Why = "Unable to verify signature, signing key missing.";
            elif Split[7] == '4':
               Why = "Unable to verify signature, unknown packet format/key type";
            else:
               Why = "Unable to verify signature, unknown reason";

         if Split[1] == "NO_PUBKEY":
            GoodSig = 0;
            Why = "Unable to verify signature, signing key missing.";

         # Expired signature
         if Split[1] == "EXPSIG":
            GoodSig = 0;
            Why = "Signature has expired";

         # Expired signature
         if Split[1] == "EXPKEYSIG":
            GoodSig = 0;
            Why = "Signing key (%s, %s) has expired"%(Split[2], Split[3]);

         # Revoked key
         if Split[1] == "KEYREVOKED" or Split[1] == "REVKEYSIG":
            GoodSig = 0;
            Why = "Signing key has been revoked";

         # Corrupted packet
         if Split[1] == "NODATA" or Split[1] == "BADARMOR":
            GoodSig = 0;
            Why = "The packet was corrupted or contained no data";

         # Signature ID
         if Split[1] == "SIG_ID":
            SigId = Split[2];
            Date = long(Split[4]);

         # ValidSig has the key finger print
         if Split[1] == "VALIDSIG":
            # Use the fingerprint of the primary key when available
            if len(Split) >= 12:
               KeyFinger = Split[11];
            else:
               KeyFinger = Split[2];

      # Reopen the stream as a readable stream
      Text = Res[2].read();

      # A gpg failure is an automatic bad signature
      if Exit[1] != 0 and Why == None:
         GoodSig = 0;
         Why = "GPG execution returned non-zero exit status: " + str(Exit[1]);

      if GoodSig == 0 and (Why == None or len(Why) == 0):
         Why = "Checking Failed";

      # Try to decide if this message was sent using PGP2
      PGP2Message = 0;
      if (re.search("-----[\n\r][\n\r]?Version: 2\\.",Message) != None):
         PGP2Message = 1;

      return (Why,(SigId,Date,KeyFinger),(KeyID,KeyFinger,Owner,0,PGP2Message),Text);
   finally:
      if Res != None:
         Res[1].close();
         Res[2].close();

class GPGCheckSig2:
        def __init__(self, msg):
                res = GPGCheckSig(msg)
                self.why = res[0]
                self.sig_info = res[1]
                self.key_info = res[2]
                self.text = res[3]

                self.ok = self.why is None

                self.sig_id = self.sig_info[0]
                self.sig_date = self.sig_info[1]
                self.sig_fpr = self.sig_info[2]

                self.key_id = self.key_info[0]
                self.key_fpr = self.key_info[1]
                self.key_owner = self.key_info[2]

                self.is_pgp2 = self.key_info[4]

# Search for keys given a search pattern. The pattern is passed directly
# to GPG for processing. The result is a list of tuples of the form:
#   (KeyID,KeyFinger,Owner,Length)
# Which is similar to the key identification tuple output by GPGChecksig
#
# Do not return keys where the primary key has expired
def GPGKeySearch(SearchCriteria):
   Args = [GPGPath] + GPGBasicOptions + GPGKeyRings + GPGSearchOptions + \
          [SearchCriteria," 2> /dev/null"]
   Strm = None
   Result = []
   Validity = None
   Length = 0
   KeyID = ""
   Capabilities = ""
   Fingerprint = ""
   Owner = ""
   Hits = {}

   dir = os.path.expanduser("~/.gnupg")
   if not os.path.isdir(dir):
      os.mkdir(dir, 0700)

   try:
      # The GPG output will contain zero or more stanza, one stanza per match found.
      # Each stanza consists of the following records, in order:
      #   tru : trust database information
      #   pub : primary key from which we extract
      #         field  1 - Validity
      #         field  2 - Length
      #         field  4 - KeyID
      #         field 11 - Capabilities
      #   fpr : fingerprint of primary key from which we extract
      #         field  9 - Fingerprint
      #   uid : first User ID attached to primary key from which we extract
      #         Field  9 - Owner
      #   uid : (optional) additional multiple User IDs attached to primary key
      #   sub : (optional) secondary key
      #   fpr : (opitonal) fingerprint of secondary key if sub is present
      Strm = os.popen(" ".join(Args),"r")
      Want = "pub"
      while(1):
         Line = Strm.readline()
         if Line == "":
            break
         Split = Line.split(":")

         if Split[0] != Want:
            continue

         if Want == 'pub':
            Validity = Split[1]
            Length = int(Split[2])
            KeyID = Split[4]
            Capabilities = Split[11]
            Want = 'fpr'
            continue

         if Want == 'fpr':
            Fingerprint = Split[9]
            if Hits.has_key(Fingerprint):
               Want = 'pub' # already seen, skip to next stanza
            else:
               Hits[Fingerprint] = None
               Want = 'uid'
            continue

         if Want == 'uid':
            Owner = Split[9]
            if Validity != 'e': # if not expired
               Result.append( (KeyID,Fingerprint,Owner,Length,Capabilities) )
            Want = 'pub' # finished, skip to next stanza
            continue

   finally:
      if Strm != None:
         Strm.close()
   return Result

# Print the available key information in a format similar to GPG's output
# We do not know the values of all the feilds so they are just replaced
# with ?'s
def GPGPrintKeyInfo(Ident):
   print "pub  %u?/%s ??-??-?? %s" % (Ident[3],Ident[0][-8:],Ident[2]);
   print "     key fingerprint = 0x%s" % (Ident[1]);

# Perform a substition of template
def TemplateSubst(Map,Template):
   for x in Map.keys():
      Template = Template.replace(x, Map[x])
   return Template;

# The replay class uses a python DB (BSD db if avail) to implement
# protection against replay. Replay is an attacker capturing the
# plain text signed message and sending it back to the victim at some
# later date. Each signature has a unique signature ID (and signing
# Key Fingerprint) as well as a timestamp. The first stage of replay
# protection is to ensure that the timestamp is reasonable, in particular
# not to far ahead or too far behind the current system time. The next
# step is to look up the signature + key fingerprint in the replay database
# and determine if it has been recived. The database is cleaned out
# periodically and old signatures are discarded. By using a timestamp the
# database size is bounded to being within the range of the allowed times
# plus a little fuzz. The cache is serialized with a flocked lock file
class ReplayCache:
   def __init__(self,Database):
      self.Lock = open(Database + ".lock","w",0600);
      fcntl.flock(self.Lock.fileno(),fcntl.LOCK_EX);
      self.DB = anydbm.open(Database,"c",0600);
      self.CleanCutOff = CleanCutOff;
      self.AgeCutOff = AgeCutOff;
      self.FutureCutOff = FutureCutOff;
      self.Clean()

   # Close the cache and lock
   def __del__(self):
      self.close();
   def close(self):
      self.DB.close();
      self.Lock.close();

   # Clean out any old signatures
   def Clean(self):
      CutOff = time.time() - self.CleanCutOff;
      for x in self.DB.keys():
         if int(self.DB[x]) <= CutOff:
            del self.DB[x];

   # Check a signature. 'sig' is a 3 tuple that has the sigId, date and
   # key ID
   def Check(self,Sig):
      if Sig[0] == None or Sig[1] == None or Sig[2] == None:
         return "Invalid signature";
      if int(Sig[1]) > time.time() + self.FutureCutOff:
         return "Signature has a time too far in the future";
      if self.DB.has_key(Sig[0] + '-' + Sig[2]):
         return "Signature has already been received";
      if int(Sig[1]) < time.time() - self.AgeCutOff:
         return "Signature has passed the age cut off ";
      # + str(int(Sig[1])) + ',' + str(time.time()) + "," + str(Sig);
      return None;

   # Add a signature, the sig is the same as is given to Check
   def Add(self,Sig):
      if Sig[0] == None or Sig[1] == None:
         raise RuntimeError,"Invalid signature";
      if Sig[1] < time.time() - self.CleanCutOff:
         return;
      Key = Sig[0] + '-' + Sig[2]
      if self.DB.has_key(Key):
         if int(self.DB[Key]) < Sig[1]:
            self.DB[Key] = str(int(Sig[1]));
      else:
         self.DB[Key] = str(int(Sig[1]));

   def process(self, sig_info):
      r = self.Check(sig_info);
      if r != None:
         raise RuntimeError, "The replay cache rejected your message: %s."%(r);
      self.Add(sig_info);
      self.close();

# vim:set et:
# vim:set ts=3:
# vim:set shiftwidth=3:
