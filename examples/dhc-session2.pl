use Net::DHCP::Session;
use strict;

my $mac= '00065B011A5C';
my $dhc = new Net::DHCP::Session(Hostname => 'YOYOMA', 
		Localaddr => '158.67.34.252', 
		Server_ip => '158.67.34.254',
		Chaddr => $mac);
$dhc->release();
