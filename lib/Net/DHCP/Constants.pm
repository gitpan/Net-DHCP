# Net::DHCP::Constants.pm
# Version 0.53
# Author: Stephan Hadinger

package Net::DHCP::Constants;

# standard module declaration
use 5.8.0;
use strict;
our (@ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS, $VERSION);
use Exporter;
$VERSION = 0.53;
@ISA = qw(Exporter);

@EXPORT = qw(MAGIC_COOKIE);

# Constants
our (%DHO_CODES, %REV_DHO_CODES);
our (%DHCP_MESSAGE, %REV_DHCP_MESSAGE);
our (%BOOTP_CODES, %REV_BOOTP_CODES);
our (%HTYPE_CODES, %REV_HTYPE_CODES);

%EXPORT_TAGS = (
  dho_codes => [keys %DHO_CODES],
  dhcp_message => [keys %DHCP_MESSAGE],
  bootp_codes => [keys %BOOTP_CODES],
  htype_codes => [keys %HTYPE_CODES],
  dhcp_hashes => [ qw(
            %DHO_CODES %REV_DHO_CODES %DHCP_MESSAGE %REV_DHCP_MESSAGE
            %BOOTP_CODES %REV_BOOTP_CODES
            %HTYPE_CODES %REV_HTYPE_CODES
            )]
  );


@EXPORT_OK = qw(
            %DHO_CODES %REV_DHO_CODES %DHCP_MESSAGE %REV_DHCP_MESSAGE
            %BOOTP_CODES %REV_BOOTP_CODES
            %HTYPE_CODES %REV_HTYPE_CODES
            MAGIC_COOKIE
            );
Exporter::export_tags('dho_codes');
Exporter::export_tags('dhcp_message');
Exporter::export_tags('bootp_codes');
Exporter::export_tags('htype_codes');

# MAGIC_COOKIE for DHCP (oterhwise it is BOOTP)
use constant MAGIC_COOKIE => "\x63\x82\x53\x63";

BEGIN {
  %BOOTP_CODES = (
    'BOOTREQUEST'     =>  0x1,
    'BOOTREPLY'       =>  0x2
    );
  
  %HTYPE_CODES = (
    'HTYPE_ETHER'     => 1,
    'HTYPE_IEEE802'   => 6,
    'HTYPE_FDDI'      => 8
    );

  %DHO_CODES = (    # rfc 2132
    'DHO_PAD' => 0,
    'DHO_SUBNET_MASK' => 1,
    'DHO_TIME_OFFSET' => 2,
    'DHO_ROUTERS' => 3,
    'DHO_TIME_SERVERS'  => 4,
    'DHO_NAME_SERVERS'  => 5,
    'DHO_DOMAIN_NAME_SERVERS' => 6,
    'DHO_LOG_SERVERS' => 7,
    'DHO_COOKIE_SERVERS'  => 8,
    'DHO_LPR_SERVERS' => 9,
    'DHO_IMPRESS_SERVERS' => 10,
    'DHO_RESOURCE_LOCATION_SERVERS' => 11,
    'DHO_HOST_NAME' => 12,
    'DHO_BOOT_SIZE' => 13,
    'DHO_MERIT_DUMP'  => 14,
    'DHO_DOMAIN_NAME' => 15,
    'DHO_SWAP_SERVER' => 16,
    'DHO_ROOT_PATH' => 17,
    'DHO_EXTENSIONS_PATH' => 18,
    'DHO_IP_FORWARDING' => 19,
    'DHO_NON_LOCAL_SOURCE_ROUTING'  => 20,
    'DHO_POLICY_FILTER' => 21,
    'DHO_MAX_DGRAM_REASSEMBLY'  => 22,
    'DHO_DEFAULT_IP_TTL'  => 23,
    'DHO_PATH_MTU_AGING_TIMEOUT'  => 24,
    'DHO_PATH_MTU_PLATEAU_TABLE'  => 25,
    'DHO_INTERFACE_MTU' => 26,
    'DHO_ALL_SUBNETS_LOCAL' => 27,
    'DHO_BROADCAST_ADDRESS' => 28,
    'DHO_PERFORM_MASK_DISCOVERY'  => 29,
    'DHO_MASK_SUPPLIER' => 30,
    'DHO_ROUTER_DISCOVERY'  => 31,
    'DHO_ROUTER_SOLICITATION_ADDRESS' => 32,
    'DHO_STATIC_ROUTES' => 33,
    'DHO_TRAILER_ENCAPSULATION' => 34,
    'DHO_ARP_CACHE_TIMEOUT' => 35,
    'DHO_IEEE802_3_ENCAPSULATION' => 36,
    'DHO_DEFAULT_TCP_TTL' => 37,
    'DHO_TCP_KEEPALIVE_INTERVAL'  => 38,
    'DHO_TCP_KEEPALIVE_GARBAGE' => 39,
    'DHO_NIS_DOMAIN'  => 40,
    'DHO_NIS_SERVERS' => 41,
    'DHO_NTP_SERVERS' => 42,
    'DHO_VENDOR_ENCAPSULATED_OPTIONS' => 43,
    'DHO_NETBIOS_NAME_SERVERS'  => 44,
    'DHO_NETBIOS_DD_SERVER' => 45,
    'DHO_NETBIOS_NODE_TYPE' => 46,
    'DHO_NETBIOS_SCOPE' => 47,
    'DHO_FONT_SERVERS'  => 48,
    'DHO_X_DISPLAY_MANAGER' => 49,
    'DHO_DHCP_REQUESTED_ADDRESS'  => 50,
    'DHO_DHCP_LEASE_TIME' => 51,
    'DHO_DHCP_OPTION_OVERLOAD'  => 52,
    'DHO_DHCP_MESSAGE_TYPE' => 53,
    'DHO_DHCP_SERVER_IDENTIFIER'  => 54,
    'DHO_DHCP_PARAMETER_REQUEST_LIST' => 55,
    'DHO_DHCP_MESSAGE'  => 56,
    'DHO_DHCP_MAX_MESSAGE_SIZE' => 57,
    'DHO_DHCP_RENEWAL_TIME' => 58,
    'DHO_DHCP_REBINDING_TIME' => 59,
    'DHO_VENDOR_CLASS_IDENTIFIER' => 60,
    'DHO_DHCP_CLIENT_IDENTIFIER'  => 61,
    'DHO_NWIP_DOMAIN_NAME'  => 62,
    'DHO_NWIP_SUBOPTIONS' => 63,
    'DHO_NIS_DOMAIN' => 64,
    'DHO_NIS_SERVER' => 65,
    'DHO_TFTP_SERVER' => 66,
    'DHO_BOOTFILE' => 67,
    'DHO_MOBILE_IP_HOME_AGENT' => 68,
    'DHO_SMTP_SERVER' => 69,
    'DHO_POP3_SERVER' => 70,
    'DHO_NNTP_SERVER' => 71,
    'DHO_WWW_SERVER' => 72,
    'DHO_FINGER_SERVER' => 73,
    'DHO_IRC_SERVER' => 74,
    'DHO_STREETTALK_SERVER' => 75,
    'DHO_STDA_SERVER' => 76,
    'DHO_USER_CLASS'  => 77,
    'DHO_FQDN'  => 81,
    'DHO_DHCP_AGENT_OPTIONS'  => 82,
    'DHO_SUBNET_SELECTION'  => 118
  );

  %DHCP_MESSAGE = (
    'DHCPDISCOVER'      => chr(1),
    'DHCPOFFER'         => chr(2),
    'DHCPREQUEST'       => chr(3),
    'DHCPDECLINE'       => chr(4),
    'DHCPACK'           => chr(5),
    'DHCPNAK'           => chr(6),
    'DHCPRELEASE'       => chr(7),
    'DHCPINFORM'        => chr(8),
    'DHCPFORCERENEW'    => chr(9),
    
    'DHCPLEASEQUERY'    => chr(13),   # Cisco extension, draft-ietf-dhc-leasequery-08.txt
    );
}

  use constant \%DHO_CODES;
  %REV_DHO_CODES = reverse %DHO_CODES;
  
  use constant \%DHCP_MESSAGE;
  %REV_DHCP_MESSAGE = reverse %DHCP_MESSAGE;
  
  use constant \%BOOTP_CODES;
  %REV_BOOTP_CODES = reverse %BOOTP_CODES;    # for reverse lookup
  
  use constant \%HTYPE_CODES;
  %REV_HTYPE_CODES = reverse %HTYPE_CODES;    # for reverse lookup
  
#
# Format of DHCP options : for pretty-printing
#   inet : 4 bytes IP address
#   inets : list of 4 bytes IP addresses
#   int : 4 bytes integer
#   short : 2 bytes intteger
#   shorts : list of 2 bytes integers
#   byte : 1 byte int
#   string : char* (just kidding)
#   hex : variable length hex value
#   opt : DHCP sub-options (rfc 3046)
#
our %DHO_FORMATS = (
    DHO_PAD() => '',
    DHO_SUBNET_MASK() => 'inet',
    DHO_TIME_OFFSET() => 'int',
    DHO_ROUTERS() => 'inets',
    DHO_TIME_SERVERS()  => 'inets',
    DHO_NAME_SERVERS()  => 'inets',
    DHO_DOMAIN_NAME_SERVERS() => 'inets',
    DHO_LOG_SERVERS() => 'inets',
    DHO_COOKIE_SERVERS()  => 'inets',
    DHO_LPR_SERVERS() => 'inets',
    DHO_IMPRESS_SERVERS() => 'inets',
    DHO_RESOURCE_LOCATION_SERVERS() => 'inets',
    DHO_HOST_NAME() => 'string',
    DHO_BOOT_SIZE() => 'short',
    DHO_MERIT_DUMP() => 'string',
    DHO_DOMAIN_NAME() => 'string',
    DHO_SWAP_SERVER() => 'inet',
    DHO_ROOT_PATH() => 'string',
    DHO_EXTENSIONS_PATH() => 'string',
    DHO_IP_FORWARDING() => 'byte',
    DHO_NON_LOCAL_SOURCE_ROUTING() => 'byte',
    DHO_POLICY_FILTER() => 'inets',
    DHO_MAX_DGRAM_REASSEMBLY() => 'short',
    DHO_DEFAULT_IP_TTL() => 'byte',
    DHO_PATH_MTU_AGING_TIMEOUT() => 'int',
    DHO_PATH_MTU_PLATEAU_TABLE()  => 'shorts',
    DHO_INTERFACE_MTU() => 'short',
    DHO_ALL_SUBNETS_LOCAL() => 'byte',
    DHO_BROADCAST_ADDRESS() => 'inet',
    DHO_PERFORM_MASK_DISCOVERY()  => 'byte',
    DHO_MASK_SUPPLIER() => 'byte',
    DHO_ROUTER_DISCOVERY()  => 'byte',
    DHO_ROUTER_SOLICITATION_ADDRESS() => 'inet',
    DHO_STATIC_ROUTES() => 'inets',
    DHO_TRAILER_ENCAPSULATION() => 'byte',
    DHO_ARP_CACHE_TIMEOUT() => 'int',
    DHO_IEEE802_3_ENCAPSULATION() => 'byte',
    DHO_DEFAULT_TCP_TTL() => 'byte',
    DHO_TCP_KEEPALIVE_INTERVAL()  => 'int',
    DHO_TCP_KEEPALIVE_GARBAGE() => 'byte',
    DHO_NIS_DOMAIN()  => 'string',
    DHO_NIS_SERVERS() => 'inets',
    DHO_NTP_SERVERS() => 'inets',
    DHO_VENDOR_ENCAPSULATED_OPTIONS() => 'string',
    DHO_NETBIOS_NAME_SERVERS()  => 'inets',
    DHO_NETBIOS_DD_SERVER() => 'inets',
    DHO_NETBIOS_NODE_TYPE() => 'hex',
    DHO_NETBIOS_SCOPE() => 'string',
    DHO_FONT_SERVERS()  => 'inets',
    DHO_X_DISPLAY_MANAGER() => 'inets',
    DHO_DHCP_REQUESTED_ADDRESS()  => 'inet',
    DHO_DHCP_LEASE_TIME() => 'int',
    DHO_DHCP_OPTION_OVERLOAD()  => 'byte',
    DHO_DHCP_MESSAGE_TYPE() => 'byte',
    DHO_DHCP_SERVER_IDENTIFIER()  => 'inet',
    DHO_DHCP_PARAMETER_REQUEST_LIST() => 'hex',
    DHO_DHCP_MESSAGE()  => 'string',
    DHO_DHCP_MAX_MESSAGE_SIZE() => 'short',
    DHO_DHCP_RENEWAL_TIME() => 'int',
    DHO_DHCP_REBINDING_TIME() => 'int',
    DHO_VENDOR_CLASS_IDENTIFIER() => 'string',
    DHO_DHCP_CLIENT_IDENTIFIER()  => 'hex',
    DHO_NWIP_DOMAIN_NAME()  => 62,
    DHO_NWIP_SUBOPTIONS() => 63,
    DHO_NIS_DOMAIN() => 'string',
    DHO_NIS_SERVER() => 'string',
    DHO_TFTP_SERVER() => 'string',
    DHO_BOOTFILE() => 'string',
    DHO_MOBILE_IP_HOME_AGENT() => 'inets',
    DHO_SMTP_SERVER() => 'inets',
    DHO_POP3_SERVER() => 'inets',
    DHO_NNTP_SERVER() => 'inets',
    DHO_WWW_SERVER() => 'inets',
    DHO_FINGER_SERVER() => 'inets',
    DHO_IRC_SERVER() => 'inets',
    DHO_STREETTALK_SERVER() => 'inets',
    DHO_STDA_SERVER() => 'inets',
    DHO_USER_CLASS()  => 77,
    DHO_FQDN()  => 81,
    DHO_DHCP_AGENT_OPTIONS()  => 'opt',   # rfc 3046
    DHO_SUBNET_SELECTION()  => 118
  );

1;

=pod

=head1 NAME

Net::DHCP::Constants - Constants for DHCP codes and options

=head1 SYNOPSIS

  use Net::DHCP::Constants;
  print "DHCP option SUBNET_MASK is ", DHO_SUBNET_MASK();

=head1 DESCRIPTION

Represents constants used in DHCP protocol, defined in RFC 1533, RFC 2132, RFC 3046.

=head1 TAGS

As mentioned above, constants can either be imported individually
or in sets grouped by tag names. The tag names are:

=over 4

=item * bootp_codes

Imports all of the basic I<BOOTP> constants.

  BOOTREQUEST
  BOOTREPLY

=item * htype_codes

Imports all I<HTYPE> (hardware address type) codes.

  HTYPE_ETHER
  HTYPE_IEEE802
  HTYPE_FDDI

Most common value is HTYPE_ETHER for C<Ethernet>.

=item * dhcp_message

Import all DHCP Message codes.

  DHCPDISCOVER
  DHCPOFFER
  DHCPREQUEST
  DHCPDECLINE
  DHCPACK
  DHCPNAK
  DHCPRELEASE
  DHCPINFORM
  DHCPFORCERENEW

=item * dho_codes

Import all DHCP option codes.

  DHO_PAD
  DHO_SUBNET_MASK
  DHO_IMPRESS_SERVERS
  DHO_RESOURCE_LOCATION_SERVERS
  DHO_SUBNET_SELECTION
  DHO_HOST_NAME
  DHO_BOOT_SIZE
  DHO_MERIT_DUMP
  DHO_DOMAIN_NAME
  DHO_SWAP_SERVER
  DHO_ROOT_PATH
  DHO_EXTENSIONS_PATH
  DHO_IP_FORWARDING
  DHO_TIME_OFFSET
  DHO_NON_LOCAL_SOURCE_ROUTING
  DHO_POLICY_FILTER
  DHO_MAX_DGRAM_REASSEMBLY
  DHO_DEFAULT_IP_TTL
  DHO_PATH_MTU_AGING_TIMEOUT
  DHO_PATH_MTU_PLATEAU_TABLE
  DHO_INTERFACE_MTU
  DHO_ALL_SUBNETS_LOCAL
  DHO_BROADCAST_ADDRESS
  DHO_PERFORM_MASK_DISCOVERY
  DHO_ROUTERS
  DHO_MASK_SUPPLIER
  DHO_ROUTER_DISCOVERY
  DHO_ROUTER_SOLICITATION_ADDRESS
  DHO_STATIC_ROUTES
  DHO_TRAILER_ENCAPSULATION
  DHO_ARP_CACHE_TIMEOUT
  DHO_IEEE802_3_ENCAPSULATION
  DHO_DEFAULT_TCP_TTL
  DHO_TCP_KEEPALIVE_INTERVAL
  DHO_TCP_KEEPALIVE_GARBAGE
  DHO_TIME_SERVERS
  DHO_NIS_SERVERS
  DHO_NTP_SERVERS
  DHO_VENDOR_ENCAPSULATED_OPTIONS
  DHO_NETBIOS_NAME_SERVERS
  DHO_NETBIOS_DD_SERVER
  DHO_NETBIOS_NODE_TYPE
  DHO_NETBIOS_SCOPE
  DHO_FONT_SERVERS
  DHO_X_DISPLAY_MANAGER
  DHO_NAME_SERVERS
  DHO_DHCP_REQUESTED_ADDRESS
  DHO_DHCP_LEASE_TIME
  DHO_DHCP_OPTION_OVERLOAD
  DHO_DHCP_MESSAGE_TYPE
  DHO_DHCP_SERVER_IDENTIFIER
  DHO_DHCP_PARAMETER_REQUEST_LIST
  DHO_DHCP_MESSAGE
  DHO_DHCP_MAX_MESSAGE_SIZE
  DHO_DHCP_RENEWAL_TIME
  DHO_DHCP_REBINDING_TIME
  DHO_DOMAIN_NAME_SERVERS
  DHO_VENDOR_CLASS_IDENTIFIER
  DHO_DHCP_CLIENT_IDENTIFIER
  DHO_NWIP_DOMAIN_NAME
  DHO_NWIP_SUBOPTIONS
  DHO_NIS_DOMAIN
  DHO_NIS_SERVER
  DHO_TFTP_SERVER
  DHO_BOOTFILE
  DHO_MOBILE_IP_HOME_AGENT
  DHO_SMTP_SERVER
  DHO_LOG_SERVERS
  DHO_POP3_SERVER
  DHO_NNTP_SERVER
  DHO_WWW_SERVER
  DHO_FINGER_SERVER
  DHO_IRC_SERVER
  DHO_STREETTALK_SERVER
  DHO_STDA_SERVER
  DHO_USER_CLASS
  DHO_COOKIE_SERVERS
  DHO_FQDN
  DHO_DHCP_AGENT_OPTIONS
  DHO_LPR_SERVERS

=back

=head1 SEE ALSO

L<Net::DHCP::Packet>, L<Net::DHCP::Options>

=head1 AUTHOR

Stephan Hadinger E<lt>shadinger@cpan.orgE<gt>.

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
