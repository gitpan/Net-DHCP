# -*- perl -*-
#
# $Id: Makefile.PL,v 0.1 2002/08/15 14:23:53 Fva Exp $
#

use ExtUtils::MakeMaker;
my @examples = qw(dhc-session.pl dhc-session2.pl);

my %opts = (
    'NAME'	=> 'Net::DHCP',
    'VERSION_FROM' => 'lib/Net/DHCP/Session.pm', # finds $VERSION
    'PREREQ_PM' => { 'IO::Socket::INET' => 0,  'Sys::Hostname' => 0,  'IO::Select' =>0},
);

if ($ExtUtils::MakeMaker::VERSION >= 5.43) {
    $opts{AUTHOR} = 'Francis van Dun (francis.vandun@pandora.be)';
}

WriteMakefile(%opts);
