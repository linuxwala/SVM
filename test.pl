#!/usr/bin/perl -w
#
# Test open_offline
#
# $Id: 06-offline.t,v 1.7 1999/05/05 02:11:56 tpot Exp $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

use Getopt::Long qw(:config posix_default bundling);

use Net::SIP ':all';



#print "Part 1:printing packets from file \n\n";


my($result,$filter,$mask,$net,$result1);



my($pcap_t, $err);
#my $dumpfile = "/tmp/Net-Pcap-dump.$$";
my $dumpfile= "dumpfiles/try1";
#my $dumpfile= "asterisk-1.cap";
#my $dumpfile1="/home/VoIP_Tools/Net-Pcap-0.05/t/dumpfiles/try1";
my $dumpfile1="dumpfiles/try2";

my $dev = Net::Pcap::lookupdev(\$err);
$result=Net::Pcap::lookupnet(\$dev,\$net,\$mask,\$err);

