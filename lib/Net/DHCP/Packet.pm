# Net::DHCP::Packet.pm
# Version 0.52
# Original Author: F. van Dun
# Author : S. Hadinger

package Net::DHCP::Packet;

# standard module declaration
use 5.8.0;
use strict;
our (@ISA, @EXPORT, @EXPORT_OK, $VERSION);
use Exporter;
$VERSION = 0.52;
@ISA = qw(Exporter);
@EXPORT = qw( packinet packinets unpackinet unpackinets );
@EXPORT_OK = qw( );

use Socket;
use Carp;
use Net::DHCP::Constants qw(:DEFAULT :dhcp_hashes);
use Scalar::Util qw(looks_like_number);		# for numerical testing

#=======================================================================
sub new {
	my $class = shift;
	
	my $self = {	options => {},					# DHCP options
								options_order => []			# order in which the options were added
						};
	bless $self, $class;
	if (scalar @_ == 1) {	# we build the packet from a binary string
		$self->marshall(shift);
	} else {
		my %args = @_;
		my @ordered_args = @_;
		$self->comment($args{Comment} || undef);
		$self->op($args{Op} || BOOTREQUEST());
		$self->htype($args{Htype} || 1);	# 10mb ethernet
		$self->hlen($args{Hlen} || 6);		# Use 6 bytes MAC by default
		$self->hops($args{Hops} || 0);
		$self->xid($args{Xid} || 0x12345678);
		$self->secs($args{Secs} || 0);
		$self->flags($args{Flags} || 0);
		$self->ciaddr($args{Ciaddr} || "0.0.0.0");
		$self->yiaddr($args{Yiaddr} || "0.0.0.0");
		$self->siaddr($args{Siaddr} || "0.0.0.0");
		$self->giaddr($args{Giaddr} || "0.0.0.0");
		$self->chaddr($args{Chaddr} || "" );
		$self->sname($args{Sname} || "");
		$self->file($args{File} || "");
		$self->padding($args{Padding} || "");
		
		$self->isDhcp($args{IsDhcp} || 1);

		# TBM add DHCP option parsing
		while (defined(my $key = shift(@ordered_args))) {
			my $value = shift(@ordered_args);
			next unless looks_like_number($key);			# skip non-numerical keys
			$self->addOption($key, $value);
		}
	}
	return $self;
}
#=======================================================================
# comment attribute : enables transaction number identification
sub comment {
    my $self = shift;
    if (@_) { $self->{comment} = shift } 
    return $self->{comment};
} 

# op attribute
sub op {
    my $self = shift;
    if (@_) { $self->{op} = shift } 
    return $self->{op};
} 

# htype attribute
sub htype {
	my $self = shift;
	if (@_) { $self->{htype} = shift }
	return $self->{htype};
}

# hlen attribute
sub hlen {
	my $self = shift;
	if (@_) { $self->{hlen} = shift }
	if ($self->{hlen} < 0)  { carp("hlen must not be < 0 (currently ".$self->{hlen}.")") }
	if ($self->{hlen} > 16) { carp("hlen must not be > 16 (currently ".$self->{hlen}.")") }
	return $self->{hlen};
}

# hops attribute
sub hops {
	my $self = shift;
	if (@_) { $self->{hops} = shift }
	return $self->{hops};
}

# xid attribute
sub xid {
	my $self = shift;
	if (@_) { $self->{xid} = shift }
	return $self->{xid};
}

# secs attribute
sub secs {
	my $self = shift;
	if (@_) { $self->{secs} = shift }
	return $self->{secs};
}

# flags attribute
sub flags {
	my $self = shift;
	if (@_) { $self->{flags} = shift }
	return $self->{flags};
}

# ciaddr attribute
sub ciaddr {
	my $self = shift;
	if (@_) { $self->{ciaddr} = packinet(shift) }
	return unpackinet($self->{ciaddr});
} 

# yiaddr attribute
sub yiaddr {
	my $self = shift;
	if (@_) { $self->{yiaddr} = packinet(shift) }
	return unpackinet($self->{yiaddr});
} 

# siaddr attribute
sub siaddr {
	my $self = shift;
	if (@_) { $self->{siaddr} = packinet(shift) }
	return unpackinet($self->{siaddr});
}

# giaddr attribute
sub giaddr {
	my $self = shift;
	if (@_) { $self->{giaddr} = packinet(shift) }
	return unpackinet($self->{giaddr});
}

# chaddr attribute
sub chaddr {
	my $self = shift;
	if (@_) { $self->{chaddr} = pack("H*", shift) }
	return unpack("H*", $self->{chaddr});
}

# sname attribute
sub sname {
	use bytes;
	my $self = shift;
	if (@_) { $self->{sname} = shift }
	if (length($self->{sname}) > 63) {
		carp("'sname' must not be > 63 bytes, (currently ".length($self->{sname}).")");
		$self->{sname} = pack("a63", $self->{sname});
	}
	return $self->{sname};
}

# file attribute
sub file {
	use bytes;
	my $self = shift;
	if (@_) { $self->{file} = shift } 
	if (length($self->{file}) > 127) {
		carp("'file' must not be > 127 bytes, (currently ".length($self->{file}).")");
		$self->{file} = pack("a127", $self->{file});
	}
	return $self->{file};
}

# is it DHCP or BOOTP
#		-> DHCP needs magic cookie and options
sub isDhcp {
	my $self = shift;
	if (@_) { $self->{isDhcp} = shift } 
	return $self->{isDhcp};
}

# padding attribute
sub padding {
	my $self = shift;
	if (@_) { $self->{padding} = shift }
	return $self->{padding};
}
#=======================================================================
sub addOption {
	my ($self,$key,$value) = @_;
	$self->{options}->{$key} = $value;
	push @{$self->{options_order}}, ($key);
}

sub getOption {
	my ($self,$key) = @_;
	return $self->{options}->{$key} if exists($self->{options}->{$key});
	return undef;
}
#=======================================================================
my $BOOTP_FORMAT = 'C C C C N n n a4 a4 a4 a4 a16 Z64 Z128 a*';
my $DHCP_MIN_LENGTH = length(pack($BOOTP_FORMAT));
#=======================================================================
sub serialize {
	use bytes;
	my ($self) = @_;
	my $bytes = undef;
	
	$bytes = pack($BOOTP_FORMAT,			
		$self->{op},
		$self->{htype},
		$self->{hlen},
		$self->{hops},
		$self->{xid},
		$self->{secs},
		$self->{flags},
		$self->{ciaddr},
		$self->{yiaddr},
		$self->{siaddr},
		$self->{giaddr},
		$self->{chaddr},
		$self->{sname},
		$self->{file}
		);
	
	if ($self->{isDhcp}) {		# add MAGIC_COOKIE and options
		$bytes .= MAGIC_COOKIE();	
		foreach my $key ( @{$self->{options_order}} ) {
			$bytes .= pack('C', $key);
			$bytes .= pack('C/a*', $self->{options}->{$key});
		}
		$bytes .= pack('C', 255);
	}
	
	$bytes .= $self->{padding};		# add optional padding
	
	# TBM verify maximum DHCP packet size
	return $bytes;
}
#=======================================================================
# TBM : verify packet minimum size
sub marshall {
	use bytes;
	my ($self, $buf) = @_;
	my $opt_buf;
	
	if (length($buf) < $DHCP_MIN_LENGTH) {
		croak("mashall: packet too small (".length($buf)."), minimum size is $DHCP_MIN_LENGTH");
	}
	
	(
	$self->{op},
	$self->{htype},
	$self->{hlen},
	$self->{hops},
	$self->{xid},
	$self->{secs},
	$self->{flags},
	$self->{ciaddr},
	$self->{yiaddr},
	$self->{siaddr},
	$self->{giaddr},
	$self->{chaddr},
	$self->{sname},
	$self->{file},
	$opt_buf ) = unpack($BOOTP_FORMAT, $buf);

	$self->{isDhcp} = 0;			# default to BOOTP
	if ((length($opt_buf) > 4) && (substr($opt_buf,0,4) eq MAGIC_COOKIE())) {
		# it is definitely DHCP
		$self->{isDhcp} = 1;

		my $pos = 4;	# Skip magic cookie
		my $total = length($opt_buf);
	
		while ($pos < $total) {
			my $type = ord(substr($opt_buf,$pos++,1));
			last if ($type eq 255);				# Type 'FF' signals end of options.
			my $len = ord(substr($opt_buf,$pos++,1));
			my $option = substr($opt_buf,$pos,$len);
			$pos += $len;
			$self->addOption($type,$option);
		}
		if ($pos < $total) {
			$self->{padding} = substr($opt_buf, $pos, $total-$pos);
		} else {
			$self->{padding} = '';
		}
	} else {
		$self->{padding} = $opt_buf;
	}
	
	return $self;
}
#=======================================================================
sub decodeRelayAgent($$) {
	use bytes;
	my $self = shift;
	my ($opt_buf) = @_;
	my %opt;
	
	if (length($opt_buf) > 1) {
		my $pos = 0;
		my $total = length($opt_buf);
	
		while ($pos < $total) {
			my $type = ord(substr($opt_buf,$pos++,1));
			my $len = ord(substr($opt_buf,$pos++,1));
			my $option = substr($opt_buf,$pos,$len);
			$pos += $len;
			$opt{$type} = $option;
		}
	}
	return %opt;
}

sub encodeRelayAgent($@) {
	use bytes;
	my $self = shift;
	my @opt = @_;
	my $buf = '';

	while (defined(my $key = shift(@opt))) {
		my $value = shift(@opt);
		$buf .= pack('C', $key);
		$buf .= pack('C/a*', $value);
	}
	return $buf;
}
#=======================================================================
sub toString {
	my ($self) = @_;
	my $s = "";
	
	$s .= sprintf("comment = %s\n", $self->comment());
	$s .= sprintf("op = %s\n", (exists($REV_BOOTP_CODES{$self->op()}) && $REV_BOOTP_CODES{$self->op()}) || $self->op());
	$s .= sprintf("htype = %s\n", (exists($REV_HTYPE_CODES{$self->htype()}) && $REV_HTYPE_CODES{$self->htype()}) || $self->htype());
	$s .= sprintf("hlen = %s\n", $self->hlen());
	$s .= sprintf("hops = %s\n", $self->hops());
	$s .= sprintf("xid = %x\n", $self->xid());
	$s .= sprintf("secs = %i\n", $self->secs());
	$s .= sprintf("flags = %x\n", $self->flags());
	$s .= sprintf("ciaddr = %s\n", $self->ciaddr());
	$s .= sprintf("yiaddr = %s\n", $self->yiaddr());
	$s .= sprintf("siaddr = %s\n", $self->siaddr());
	$s .= sprintf("giaddr = %s\n", $self->giaddr());
	$s .= sprintf("chaddr = %s\n", substr($self->chaddr(),0,2 * $self->hlen()));
	$s .= sprintf("sname = %s\n", $self->sname());
	$s .= sprintf("file = %s\n", $self->file());
	$s .= "Options : \n";
	
	foreach my $key ( @{$self->{options_order}} ) {
		my ($raw_value, $value);
		$raw_value = $value = $self->{options}->{$key};		# display in string format by default
		
		if (exists $Net::DHCP::Constants::DHO_FORMATS{$key}) {
			my $form = $Net::DHCP::Constants::DHO_FORMATS{$key};
			
			if 		($key == DHO_DHCP_MESSAGE_TYPE()) { $value = (exists($REV_DHCP_MESSAGE{$raw_value}) && $REV_DHCP_MESSAGE{$raw_value}) || $raw_value }
			elsif ($form eq 'inet')   { $value = unpackinet($raw_value) }
			elsif ($form eq 'inets')  { $value = unpackinets($raw_value) }
			elsif ($form eq 'hex')    { $value = unpack("H*", $raw_value) }
			elsif ($form eq 'opt')		{ $value = unpackRelayAgent($self->decodeRelayAgent($raw_value)) }
			elsif ($form eq 'byte')		{ $value = unpack("C", $raw_value) }
			elsif ($form eq 'short')	{ $value = unpack("n", $raw_value) }
			elsif ($form eq 'int')    { $value = unpack("N", $raw_value) }
			elsif ($form eq 'shorts')	{ $value = join(" ", unpack("n", $raw_value)) }
			elsif ($form eq 'string')	{ $value = $raw_value }
		}
		
		$s .= sprintf(" %s(%d) = %s\n", exists $REV_DHO_CODES{$key} ? $REV_DHO_CODES{$key}: '', $key, $value);
	}
	$s .= sprintf("padding [%s] = %s\n", length($self->{padding}), $self->{padding});
	
	return $s;
}
#=======================================================================
# internal utility functions
# never failing versions of the "Socket" module functions
sub unpackinet($) {		# bullet-proof version, never complains
	return join('.', unpack('C4', shift));
}

sub packinet($) {		# bullet-proof version, never complains
	return pack('C4', split(/\./, shift));
}

sub packinets($) {		# multiple ip addresses, space delimited
	return join('', map(pack('C4', split(/\./, $_)), split(/\s+/, shift)));
}

sub unpackinets($) {	# multiple ip addresses
	return join(" ", map(join('.', unpack('C4', $_)), unpack("(a4)*", shift)));
}

sub unpackRelayAgent(%) { # prints a human readable 'relay agent options'
	my %relay_opt = @_;
	return join(",", map { "($_)=".$relay_opt{$_} } (sort keys %relay_opt));
}

#=======================================================================

1;

=pod

=head1 NAME

Net::DHCP::Packet - Object methods to create a DHCP packet.

=head1 SYNOPSIS

   use Net::DHCP::Packet;

   my $p = new Net::DHCP::Packet->new(
        'Chaddr' => '000BCDEF', 
        'Xid' => 0x9F0FD,
        'Ciaddr' => '0.0.0.0',
        'Siaddr' => '0.0.0.0', 'Hops' => 0);

=head1 DESCRIPTION

Represents a DHCP packet as specified in RFC 1533, RFC 2132.

=head1 CONSTRUCTOR

This module only provides basic constructor. For "easy" constructors, you can use
the L<Net::DHCP::Session> module.  

=over 4

=item new ( BUFFER )

=item new ( [%ARGS] )

Creates an C<Net::DHCP::Packet> object, which can be used to send or receive
DHCP network packets. BOOTP is not supported.

Without argument, a default empty packet is created.

	$packet = Net::DHCP::Packet();

A C<BUFFER> argument is interpreted as a binary buffer like one provided
by the socket C<recv()> function. if the packet is malformed, a fatal error
is issued.

   use IO::Socket::INET;
   use Net::DHCP::Packet;
   
   $sock = IO::Socket::INET->new(LocalPort => 67, Proto => "udp", Broadcast => 1)
           or die "socket: $@";
           
   while ($sock->recv($newmsg, 1024)) {
       $packet = Net::DHCP::Packet->new($newmsg);
       print $packet->toString();
   }

To create a fresh new packet C<new> takes arguments as a key-value pairs :

   ARGUMENT   FIELD      OCTETS       DESCRIPTION
   --------   -----      ------       -----------
   
   Op         op            1  Message op code / message type.
                               1 = BOOTREQUEST, 2 = BOOTREPLY
   Htype      htype         1  Hardware address type, see ARP section in "Assigned
                               Numbers" RFC; e.g., '1' = 10mb ethernet.
   Hlen       hlen          1  Hardware address length (e.g.  '6' for 10mb
                               ethernet).
   Hops       hops          1  Client sets to zero, optionally used by relay agents
                               when booting via a relay agent.
   Xid        xid           4  Transaction ID, a random number chosen by the
                               client, used by the client and server to associate
                               messages and responses between a client and a
                               server.
   Secs       secs          2  Filled in by client, seconds elapsed since client
                               began address acquisition or renewal process.
   Flags      flags         2  Flags (see figure 2).
   Ciaddr     ciaddr        4  Client IP address; only filled in if client is in
                               BOUND, RENEW or REBINDING state and can respond
                               to ARP requests.
   Yiaddr     yiaddr        4  'your' (client) IP address.
   Siaddr     siaddr        4  IP address of next server to use in bootstrap;
                               returned in DHCPOFFER, DHCPACK by server.
   Giaddr     giaddr        4  Relay agent IP address, used in booting via a
                               relay agent.
   Chaddr     chaddr       16  Client hardware address.
   Sname      sname        64  Optional server host name, null terminated string.
   File       file        128  Boot file name, null terminated string; "generic"
                               name or null in DHCPDISCOVER, fully qualified
                               directory-path name in DHCPOFFER.
   IsDhcp     isDhcp        4  Controls whether the packet is BOOTP or DHCP.
                               DHCP conatains the "magic cookie" of 4 bytes.
                               0x63 0x82 0x53 0x63.
   DHO_* code                  Optional parameters field.  See the options
                               documents for a list of defined options.
                               See Net::DHCP::Constants.
   Padding    padding       *  Optional padding at the end of the packet

See below methods for values and syntax descrption.

=back

=head1 METHODS

=head2 ATTRIBUTE METHODS

=over 4

=item op ( [BYTE] )

Sets/gets the I<BOOTP opcode>.

Normal values are:
	BOOTREQUEST()
	BOOTREPLY()

=item htype ( [BYTE] )

Sets/gets the I<hardware address type>.

Common value is: C<HTYPE_ETHER()> (1) = ethernet

=item hlen ( [BYTE] )

Sets/gets the I<hardware address length>. Value must be between C<0> and C<16>.

For most NIC's, the MAC address has 6 bytes.

=item hops ( [BYTE] )

Sets/gets the I<number of hops>.

This field is incremented by each encountered DHCP relay agent.	

=item xid ( [INTEGER] )

Sets/gets the 32 bits I<transaction id>.

=item secs ( [SHORT] )

Sets/gets the 16 bits I<elapsed boot time> in seconds.

=item flags ( [SHORT] )

Sets/gets the 16 bits I<flags>.

	0x8000 = Broadcast reply requested.

=item ciaddr ( [STRING])

Sets/gets the I<client IP address>.

IP address is only accepted as a string like '10.24.50.3'.

=item yiaddr ( [STRING] )

Sets/gets the I<your IP address>.

IP address is only accepted as a string like '10.24.50.3'.

=item siaddr ( [STRING] )

Sets/gets the I<next server IP address>.

IP address is only accepted as a string like '10.24.50.3'.

=item giaddr ( [STRING] )

Sets/gets the I<relay agent IP address>.

IP address is only accepted as a string like '10.24.50.3'.

=item chaddr ( [STRING] )

Sets/gets the I<client hardware address>. Its length is given by the C<hlen> attribute.

Valude is formatted as an Hexadecimal string representation.

	Example: "0010A706DFFF" for 6 bytes mac address.

Note : internal format is packed bytes string.

=item sname ( [STRING] )

Sets/gets the "server host name". Maximum size is 63 bytes. If greater
a warning is issued.

Note : internal format is null terminated string.

=item file ( [STRING] )

Sets/gets the "boot file name". Maximum size is 127 bytes. If greater
a warning is issued.

Note : internal format is null terminated string.

=item isDhcp ( [BOOLEAN] )

Sets/gets the I<DHCP cookie>. Returns whether the cookie is valid or not,
hence whether the packet is DHCP or BOOTP.

Default value is C<1>, valid DHCP cookie.

=item padding ( [BYTES] )

Sets/gets the optional padding at the end of the DHCP packet, i.e. after
DHCP options.

=item addOption ( CODE, VALUE )

Adds a DHCP option field. Common code values are listed in
C<Net::DHCP::Constants> C<DHO_>*.

Warning: values must be in packed binary format, depending on the
code value, as described in RFC 2132. No control is done.

   $packet = new Net::DHCP::Packet->new();
   $packet->addOption(DHO_DHCP_MESSAGE_TYPE(), DHCPINFORM());
   $packet->addOption(DHO_NAME_SERVERS(), packinets("10.0.0.1 10.0.0.2"));

=item getOption ($type)

Returns the value of a DHCP option.

Warning: values are returned as packed binary strings, as described if
RFC 2132.

=back

=head2 SERIALIZATION METHODS

=over 4

=item serialize ()

Converts a Net::DHCP::Packet to a string, ready to put on the network.

=item marshall ( BYTES )

The inverse of serialize. Converts a string, presumably a 
received UDP packet, into a Net::DHCP::Packet.

If the packet is malformed, a fatal error is produced.

=back

=head2 HELPER METHODS

=over 4

=item toString ()

Returns a textual representation of the packet, for debugging.

=item packinet ( STRING )

Transforms a IP address "xx.xx.xx.xx" into a packed 4 bytes string.

These are simple never failing versions of inet_ntoa and inet_aton.

=item packinets ( STRING )

Transforms a list of space delimited IP addresses into a packed bytes string.

=item unpackinet ( STRING )

Transforms a packed bytes IP address into a "xx.xx.xx.xx" string.

=item unpackinets ( STRING )

Transforms a packed bytes liste of IP addresses into a list of
"xx.xx.xx.xx" space delimited string.

=back

=head1 EXAMPLES

Sending a simple DHCP packet:

	#!/usr/bin/perl
	# Simple DHCP client - sending a broadcasted DHCP Discover request
	
	use IO::Socket::INET;
	use Net::DHCP::Packet;
	use Net::DHCP::Constants;
	
	# creat DHCP Packet
	$discover = Net::DHCP::Packet->new(
	                      op => BOOTREQUEST(),
	                      xid => int(rand(0xFFFFFFFF)), # random xid
	                      Flags => 0x8000,              # ask for broadcast answer
	                      DHO_DHCP_MESSAGE_TYPE() => DHCPDISCOVER()
	                      );
	
	# send packet
	$handle = IO::Socket::INET->new(Proto => 'udp',
	                                Broadcast => 1,
	                                PeerPort => '67',
	                                LocalPort => '68',
	                                PeerAddr => '255.255.255.255')
	              or die "socket: $@";     # yes, it uses $@ here
	$handle->send($discover->serialize())
	              or die "Error sending broadcast inform:$!\n";

Sniffing DHCP packets.

	#!/usr/bin/perl
	# Simple DHCP server - listen to DHCP packets and print them
	
	use IO::Socket::INET;
	use Net::DHCP::Packet;
	$sock = IO::Socket::INET->new(LocalPort => 67, Proto => "udp", Broadcast => 1)
	        or die "socket: $@";
	while ($sock->recv($newmsg, 1024)) {
	        $packet = Net::DHCP::Packet->new($newmsg);
	        print $packet->toString();
	}

=head1 AUTHOR

Stephan Hadinger E<lt>shadinger@cpan.orgE<gt>.
Original version by F. van Dun.

=head1 BUGS

I only ran some simple tests on Windows 2000 with a W2K DHCP server and 
a USR DHCP server.
Not yet tested on Unix platform.

=head1 COPYRIGHT

This is free software. It can be distributed and/or modified under the same terms as
Perl itself.

=head1 SEE ALSO

L<Net::DHCP::Options>, L<Net::DHCP::Constants>.

=cut
