#!/usr/bin/perl

# $Id: fetchkey.cgi,v 1.2 1999/09/26 01:20:39 tausq Exp $
# (c) 1999 Randolph Chung. Licensed under the GPL. <tausq@debian.org>

use strict;
use CGI;
use Util;

# Global settings...
my %config = &Util::ReadConfigFile;

my $query = new CGI;
print "Content-type: text/plain\n\n";

my $fp = $query->param('fingerprint');

if ($fp) {
  my $key = &Util::FetchKey($fp);
  if ($key) {
    print $key;
  } else {
    print "Sorry, no key found matching fingerprint $fp\n";
  }
} else {
  print "No fingerprint given\n";
}

exit 0;

