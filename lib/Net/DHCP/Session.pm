# Net::DHCP::Session.pm
# Version 0.0
# Author: F. van Dun
#

package Net::DHCP::Session;
use strict;
use Carp;
use IO::Socket::INET;
use Sys::Hostname;
use Net::DHCP::Options;
use Net::DHCP::Packet;
use vars qw($VERSION);
use IO::Select;

$VERSION=0.1;

my $ops = new Net::DHCP::Options; # Shortcut use static declarations, instead of Net::DHCP::Options.

sub genMAC {
	my $tmp_mac = "00";
	my $i = 0;
	while ($i++ < 5 ) {
		$tmp_mac.= sprintf("%x",int rand 16);
		$tmp_mac.= sprintf("%x",int rand 16);
	}
	return ($tmp_mac);
}

=pod

=head1 NAME

Net::DHCP::Session - Object methods to simulate a DHCP pc.

=head1 SYNOPSIS

=head1 DESCRIPTION

Represents a DHCP packet as specified in RFC 1533, RFC 2132.

=head2 CONSTRUCTORS

=item new

=head2 METHODS

=cut

=pod

=item new(%ARGS)

	The hash %ARGS  can contain any of these keys:
	
=cut

sub new {
	my ($class, %args)	= @_;
	
	my $self = {};
	bless $self, $class;
	$self->{chaddr} = $args{Chaddr} || Net::DHCP::Packet::randomstring(6);
	$self->{hostname} = $args{Hostname};
	$self->{request_ip} = $args{Request_ip};
	$self->{server_ip} =  $args{Server_ip};
	$self->{localaddr} =  $args{Localaddr} || inet_ntoa ( scalar ( gethostbyname(hostname()) ) );
	$self->{xid} = undef;
	$self->{ciaddr} = $args{Ciaddr};
	$self->init();
	return $self;
}

sub _getoptions {
	my ($self,$packet) = @_;
	$self->{server_ip} = inet_ntoa($packet->getOption($ops->SERVER_IP() ) ) if ( $packet->getOption($ops->SERVER_IP() ) );
	$self->{lease_time} = unpack('N',$packet->getOption($ops->LEASE_TIME()) ) if  ($packet->getOption($ops->LEASE_TIME()) );
	$self->{subnet_mask} = inet_ntoa($packet->getOption($ops->SUBNET_MASK() ) ) if ($packet->getOption($ops->SUBNET_MASK() ));
	if ($packet->getOption($ops->GATEWAY_ADDRESS())) {
		my $n = length($packet->getOption($ops->GATEWAY_ADDRESS()))/4 ;					# 4 bytes per router
		$self->{router} =  join ( ':', map {inet_ntoa($_)} unpack("a4" x $n, $packet->getOption($ops->GATEWAY_ADDRESS()) ) );
	}
	
	$self->{domain} = $packet->getOption($ops->DOMAIN() );
}

sub dumpoptions {
	my ($self) = @_;
	my $s = '';
	$s .= "DHCP server ip = $self->{server_ip} ,\n" if ($self->{server_ip});
	$s .= "lease time = $self->{lease_time},\n"  if ($self->{lease_time});
	$s .= "mask = $self->{subnet_mask},\n" if ($self->{subnet_mask});
	$s .= "router = $self->{router},\n" if ($self->{router});
	$s .= "domain = $self->{domain}\n" if ($self->{domain});
	return $s;
}

sub init {
	my ($self) = @_;

	if ($self->{server_ip} && $self->{server_ip} ne '255.255.255.255') {
		$self->{sock} = IO::Socket::INET->new(
					PeerAddr => $self->{server_ip},
					PeerPort => '67',
					LocalPort => '68',
					LocalAddr => $self->{localaddr},
					Proto    => 'udp') || die "Socket creation error: $!\n";
	} else {
		$self->{sock} = IO::Socket::INET->new(
					LocalPort => '68',
					LocalAddr => $self->{localaddr},
					Proto    => 'udp') || die "Socket broadcast creation error: $!\n";
		$self->{BCAST} = 1;
		$self->{bcastaddr} = sockaddr_in("67",inet_aton("255.255.255.255"));
	}
}

sub discover {
	my ($self) = @_;
	
	my $pdiscover = Net::DHCP::Packet->discover(Chaddr => $self->{chaddr}, Hostname => $self->{hostname});
	$self->{xid} = $pdiscover->xid() unless $self->{xid};
	$self->{sock}->send($pdiscover->serialize()) || die "Error sending discovery:$!\n";
	print "sent dhcp discover...\n";	
}

sub await_offer {
	my ($self) = @_;

	my $preply; 
	do {
		my $buf;
		print "Waiting for Offer.\n"; 
		$self->{sock}->recv($buf,3000) || die "recv offer:$!\n";
	
		$preply = new Net::DHCP::Packet()->marshall($buf);	
		print "Got a packet...\n";
	 	#print $preply->toString();	
	} until ( $preply->xid() eq $self->{xid} );
	exit(1) unless ($preply->getOption(Net::DHCP::Options::MESSAGE_TYPE()) eq Net::DHCP::Options::OFFER());
	$self->{server_ip} = inet_ntoa($preply->getOption(Net::DHCP::Options::SERVER_IP() ) );
}

sub request {
	my ($self) = @_;
	my $prequest = Net::DHCP::Packet->request(Chaddr => $self->{chaddr}, Hostname => $self->{hostname}, Xid => $self->{xid}, Server_ip => $self->{server_ip});
	$self->{sock}->send($prequest->serialize()) || die "Error sending request:$!\n";
	print "Sent request.\n";
}

sub renew {
	my ($self) = @_;
	my $prequest = Net::DHCP::Packet->request(Chaddr => $self->{chaddr}, Hostname => $self->{hostname});
	$self->{sock}->send($prequest->serialize()) || die "Error sending request:$!\n";
	print "Sent request.\n";
}

sub inform {
	my ($self) = @_;
	$self->{ciaddr} = $self->{localaddr};
	my $pinform = Net::DHCP::Packet->inform(Chaddr => $self->{chaddr}, Hostname => $self->{hostname}, Ciaddr => $self->{ciaddr});
	
	if ($self->{BCAST}) {
		$self->{sock}->sockopt(SO_BROADCAST,1);
		$self->{sock}->send($pinform->serialize(),0,$self->{bcastaddr}) || die "Error sending broadcast inform:$!\n";
	} else {
		$self->{sock}->send($pinform->serialize()) || die "Error sending inform:$!\n";
	}
	print "Sent inform.\n";
}


sub await_ack {
	my ($self) = @_;
	my $ACK=0;
	my $preply2;
	do {
		my $buf;
		print "Waiting for ACK.\n"; 
		$self->{sock}->recv($buf,3000) || die "recv ack:$!\n";
		$preply2 = new Net::DHCP::Packet()->marshall($buf);
		print "Got a packet...\n"; 
	} until ($preply2->xid() eq $self->{xid});
	
	for ( $preply2->getOption(Net::DHCP::Options::MESSAGE_TYPE()) ) {
		($_ eq Net::DHCP::Options::NAK) && do {
			print "DHCP request refused by ".$preply2->siaddr().".\n";	
			last;
		};
		($_ eq Net::DHCP::Options::ACK) &&  do {
			print "Got IP address " . $preply2->yiaddr()." for $self->{chaddr}.\n";
			$self->{ciaddr} = $preply2->yiaddr();
			$ACK=1;
			$self->_getoptions($preply2);
			last;
		};
	}
	#
}

sub release {
	my ($self) = @_;
	my $prelease = Net::DHCP::Packet->release(Server_ip => $self->{server_ip}, 
						Chaddr => $self->{chaddr}, 
						Ciaddr => $self->{ciaddr},
						Hostname => $self->{hostname}
	);
	
	$self->{sock}->send($prelease->serialize()) || die "Error sending release:$!\n";
	print "Released address.\n";
}

sub await_informacks {
	my ($self) = @_;
	my $sel = new IO::Select( $self->{sock} ) || die "select failure : $!\n";

	my $buff;    
	while($sel->can_read(10))
	{
    		print "receiving...\n";
    		my $remote = $self->{sock}->recv($buff,3000);
    		my $preply = new Net::DHCP::Packet()->marshall($buff);	
    		$self->_getoptions($preply);
    		print $self->dumpoptions();
	}
}

1;