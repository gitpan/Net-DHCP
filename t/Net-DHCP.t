#!/usr/bin/perl -wT

use Test::More tests => 4;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }
BEGIN { use_ok( 'Net::DHCP::Constants' ); }

use strict;
my $str200 = "1234567890" x 20;

my $ref_packet = unpack("u", <<'');
M`0$&`!$B,T0``(``"@```0H```(*```#"@``!!(T5GB0$C16>)`2-%9XD!(Q
M,C,T-38W.#DP,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W.#DP,3(S-#4V
M-S@Y,#$R,S0U-C<X.3`Q,C,`,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W
M.#DP,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W.#DP,3(S-#4V-S@Y,#$R
M,S0U-C<X.3`Q,C,T-38W.#DP,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W
M.#DP,3(S-#4V-P!C@E-C-0$!-@QX-#1X,S-X,C)X,3$S!C$R,S0U-@$,>$9&
M>$9&>$9&>#`P`PQX,3%X,C)X,S-X-#0A&'@R,G@S,W@T-'@U-7A&1GA&1GA&
M1G@P,"H,>#,S>#0T>#4U>#8V2`QX-#1X-35X-C9X-S?_,3(S-#4V-S@Y,#$R
M,S0U-C<X.3`Q,C,T-38W.#DP,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W
M.#DP,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W.#DP,3(S-#4V-S@Y,#$R
M,S0U-C<X.3`Q,C,T-38W.#DP,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W
M.#DP,3(S-#4V-S@Y,#$R,S0U-C<X.3`Q,C,T-38W.#DP,3(S-#4V-S@Y,#$R
(,S0U-C<X.3``

sub packinet($) {		# bullet-proof version, never complains
	return pack('C4', split(/\./, shift));
}

warn "Warnings are OK.";
my $packet = Net::DHCP::Packet->new(
											op => BOOTREQUEST(),
											Htype => HTYPE_ETHER(),
											Hlen => 6,
											Hops => 0,
											Xid => 0x11223344,
											Flags => 0x8000,
											Ciaddr => "10.0.0.1",
											Yiaddr => "10.0.0.2",
											Siaddr => "10.0.0.3",
											Giaddr => "10.0.0.4",
											Chaddr => $str200,
											Sname => $str200,
											File => $str200,
											DHO_DHCP_MESSAGE_TYPE() => DHCPDISCOVER(),
											DHO_DHCP_SERVER_IDENTIFIER() => "x44x33x22x11",
											DHO_DHCP_LEASE_TIME() => 123456,
											DHO_SUBNET_MASK() => "xFFxFFxFFx00",
											DHO_ROUTERS() => "x11x22x33x44",
											DHO_STATIC_ROUTES() => "x22x33x44x55xFFxFFxFFx00",
											DHO_NTP_SERVERS() => "x33x44x55x66",
											DHO_WWW_SERVER() => "x44x55x66x77",
											Padding => $str200
											);

#print STDERR "\n", pack("u", $packet->serialize()), "\n";
is($packet->serialize(), $ref_packet);

my $packet2 = Net::DHCP::Packet->new($ref_packet);
is($packet2->serialize(), $ref_packet);

