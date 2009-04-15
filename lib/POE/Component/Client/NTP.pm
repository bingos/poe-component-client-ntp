package POE::Component::Client::NTP;

use strict;
use warnings;
use Carp;
use IO::Socket::INET;
use Socket;
use POE;
use vars qw($VERSION);

$VERSION = '0.02';

our %MODE = (
      '0'    =>    'reserved',
      '1'    =>    'symmetric active',
      '2'    =>    'symmetric passive',
      '3'    =>    'client',
      '4'    =>    'server',
      '5'    =>    'broadcast',
      '6'    =>    'reserved for NTP control message',
      '7'    =>    'reserved for private use'
);

our %STRATUM = (
      '0'          =>    'unspecified or unavailable',
      '1'          =>    'primary reference (e.g., radio clock)',
);

for(2 .. 15){
    $STRATUM{$_} = 'secondary reference (via NTP or SNTP)';
}

for(16 .. 255){
    $STRATUM{$_} = 'reserved';
}

our %STRATUM_ONE_TEXT = (
    'LOCL'    => 'uncalibrated local clock used as a primary reference for a subnet without external means of synchronization',
    'PPS'     => 'atomic clock or other pulse-per-second source individually calibrated to national standards',
    'ACTS'  => 'NIST dialup modem service',
    'USNO'  => 'USNO modem service',
    'PTB'   => 'PTB (Germany) modem service',
    'TDF'   => 'Allouis (France) Radio 164 kHz',
    'DCF'   => 'Mainflingen (Germany) Radio 77.5 kHz',
    'MSF'   => 'Rugby (UK) Radio 60 kHz',
    'WWV'   => 'Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz',
    'WWVB'  => 'Boulder (US) Radio 60 kHz',
    'WWVH'  => 'Kaui Hawaii (US) Radio 2.5, 5, 10, 15 MHz',
    'CHU'   => 'Ottawa (Canada) Radio 3330, 7335, 14670 kHz',
    'LORC'  => 'LORAN-C radionavigation system',
    'OMEG'  => 'OMEGA radionavigation system',
    'GPS'   => 'Global Positioning Service',
    'GOES'  => 'Geostationary Orbit Environment Satellite',
);

our %LEAP_INDICATOR = (
      '0'    =>     'no warning',
      '1'    =>     'last minute has 61 seconds',
      '2'    =>     'last minute has 59 seconds)',
      '3'    =>     'alarm condition (clock not synchronized)'
);

{

    use constant NTP_ADJ => 2208988800;

    my @ntp_packet_fields = 
    (
        'Leap Indicator',
        'Version Number',
        'Mode',
        'Stratum',
        'Poll Interval',
        'Precision',
        'Root Delay',
        'Root Dispersion',
        'Reference Clock Identifier',
        'Reference Timestamp',
        'Originate Timestamp',
        'Receive Timestamp',
        'Transmit Timestamp',
    );

    my $frac2bin = sub {
        my $bin  = '';
        my $frac = shift;
        while ( length($bin) < 32 ) {
            $bin  = $bin . int( $frac * 2 );
            $frac = ( $frac * 2 ) - ( int( $frac * 2 ) );
        }
        return $bin;
    };

    my $bin2frac = sub {
        my @bin = split '', shift;
        my $frac = 0;
        while (@bin) {
            $frac = ( $frac + pop @bin ) / 2;
        }
        return $frac;
    };

    my $percision = sub{
        my $number = shift;
        if($number > 127){
            $number -= 255;
        }
        return sprintf("%1.4e", 2**$number);
    };

    my $unpack_ip = sub {
        my $ip;
        my $stratum = shift;
        my $tmp_ip = shift;
        if($stratum < 2){
            $ip = unpack("A4", 
                pack("H8", $tmp_ip)
            );
        }else{
            $ip = sprintf("%d.%d.%d.%d",
                unpack("C4",
                    pack("H8", $tmp_ip)
                )
            );
        }
        return $ip;
    };

sub get_ntp_response {
  my $package = shift;
  my %opts = @_;
  $opts{lc $_} = delete $opts{$_} for keys %opts;
  croak "$package requires an 'event' argument\n"
	unless $opts{event};
  my $options = delete $opts{options};
  $opts{host} = 'localhost' unless $opts{host};
  $opts{port} = 123 unless $opts{port} and $opts{port} =~ /^\d+$/;
  my $self = bless \%opts, $package;
  $self->{session_id} = POE::Session->create(
     object_states => [
	$self => [qw(_start _socket _dispatch _get_datagram _timeout)],
     ],
     heap => $self,
     ( ref($options) eq 'HASH' ? ( options => $options ) : () ),
  )->ID();
  return $self;
}

sub _start {
  my ($kernel,$sender,$self) = @_[KERNEL,SENDER,OBJECT];
  $self->{session_id} = $_[SESSION]->ID();
  if ( $kernel == $sender and !$self->{session} ) {
	croak "Not called from another POE session and 'session' wasn't set\n";
  }
  my $sender_id;
  if ( $self->{session} ) {
    if ( my $ref = $kernel->alias_resolve( $self->{session} ) ) {
	$sender_id = $ref->ID();
    }
    else {
	croak "Could not resolve 'session' to a valid POE session\n";
    }
  }
  else {
    $sender_id = $sender->ID();
  }
  $kernel->refcount_increment( $sender_id, __PACKAGE__ );
  $self->{sender_id} = $sender_id;
  $kernel->detach_myself();
  $kernel->yield('_socket');
  return;
}

sub _socket {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my $socket = IO::Socket::INET->new( Proto => 'udp' );
  $kernel->select_read( $socket, '_get_datagram' );
  my $server_address = pack_sockaddr_in( $self->{port}, inet_aton($self->{host}) );
  my $client_localtime      = time();
  my $client_adj_localtime  = $client_localtime + NTP_ADJ;
  my $client_frac_localtime = $frac2bin->($client_adj_localtime);

  my $ntp_msg =
    pack( "B8 C3 N10 B32", '00011011', (0) x 12, int($client_localtime),
    $client_frac_localtime );

  unless ( send( $socket, $ntp_msg, 0, $server_address ) == length($ntp_msg) ) {
    $self->{error} = $!;
    $kernel->yield('_dispatch');
    return;
  }

  $kernel->delay( '_timeout', ( $self->{timeout} || 60 ), $socket );
  return;
}

sub _timeout {
  my ($kernel,$self,$socket) = @_[KERNEL,OBJECT,ARG0];
  $kernel->select_read( $socket );
  $self->{error} = 'Socket timeout';
  $kernel->yield('_dispatch');
  return;
}

sub _get_datagram {
  my ($kernel,$self,$socket) = @_[KERNEL,OBJECT,ARG0];
  $kernel->delay( '_timeout' );
  $kernel->select_read( $socket );
  my $remote_address = recv( $socket, my $data = '', 960, 0 );
  unless ( defined $remote_address ) {
    $self->{error} = $!;
    $kernel->yield('_dispatch');
    return;
  }
  my %tmp_pkt;
  my %packet;
  my @ntp_fields = qw/byte1 stratum poll precision/;
  push @ntp_fields, qw/delay delay_fb disp disp_fb ident/;
  push @ntp_fields, qw/ref_time ref_time_fb/;
  push @ntp_fields, qw/org_time org_time_fb/;
  push @ntp_fields, qw/recv_time recv_time_fb/;
  push @ntp_fields, qw/trans_time trans_time_fb/;

  @tmp_pkt{@ntp_fields} =
      unpack( "a C3   n B16 n B16 H8   N B32 N B32   N B32 N B32", $data ); 

  @packet{@ntp_packet_fields} = (
        (unpack( "C", $tmp_pkt{byte1} & "\xC0" ) >> 6),
        (unpack( "C", $tmp_pkt{byte1} & "\x38" ) >> 3),
        (unpack( "C", $tmp_pkt{byte1} & "\x07" )),
        $tmp_pkt{stratum},
        (sprintf("%0.4f", $tmp_pkt{poll})),
        $tmp_pkt{precision} - 255,
        ($bin2frac->($tmp_pkt{delay_fb})),
        (sprintf("%0.4f", $tmp_pkt{disp})),
        $unpack_ip->($tmp_pkt{stratum}, $tmp_pkt{ident}),
        (($tmp_pkt{ref_time} += $bin2frac->($tmp_pkt{ref_time_fb})) -= NTP_ADJ),
        (($tmp_pkt{org_time} += $bin2frac->($tmp_pkt{org_time_fb})) ),
      (($tmp_pkt{recv_time} += $bin2frac->($tmp_pkt{recv_time_fb})) -= NTP_ADJ),
     (($tmp_pkt{trans_time} += $bin2frac->($tmp_pkt{trans_time_fb})) -= NTP_ADJ)
  );

  $self->{response} = \%packet;
  $kernel->yield('_dispatch');
  return;
}

sub _dispatch {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my $data = { };
  $data->{$_} = $self->{$_} for grep { defined $self->{$_} } qw(response error context);
  $kernel->post( $self->{sender_id}, $self->{event}, $data );
  $kernel->refcount_decrement( $self->{sender_id}, __PACKAGE__ );
  return;
}

}

'What is the time, Mr Wolf?';
__END__

=head1 NAME

POE::Component::Client::NTP - A POE Component to query NTP servers

=head1 SYNOPSIS

  use strict;
  use warnings;
  use POE qw(Component::Client::NTP);
  use Data::Dumper;
  
  my $host = shift or die "Please specify a host name to query\n";
  
  POE::Session->create(
    package_states => [
  	main => [qw(_start _response)],
    ],
  );
  
  $poe_kernel->run();
  exit 0;
  
  sub _start {
    POE::Component::Client::NTP->get_ntp_response(
       host => $host,
       event => '_response',
    );
    return;
  }
  
  sub _response {
    my $packet = $_[ARG0];
    print Dumper( $packet );
    return;
  }

=head1 DESCRIPTION

POE::Component::Client::NTP is a L<POE> component that provides Network Time Protocol (NTP) client 
services to other POE sessions and components.

NTP is a protocol for synchronising the clocks of computer systems over data networks and is described in 
RFC 1305 and RFC 2030.

The code in this module is derided from L<Net::NTP> by James G. Willmore

=head1 CONSTRUCTOR

=over 

=item C<get_ntp_response>

Takes a number of options, only those marked as C<mandatory> are required:

  'event', the event to emit when completed, mandatory;
  'session', provide an alternative session to send the resultant event to;
  'host', the name/address of the NTP server to query, default is 'localhost';
  'port', the UDP port to send the query to, default is 123;
  'timeout', the number of seconds to wait for a response, default is 60 seconds;
  
The C<session> parameter is only required if you wish the output event to go to a different session than the calling session, 
or if you have spawned the poco outside of a session.

=back

=head1 OUTPUT EVENT

This is generated by the poco. C<ARG0> will be a hash reference with the following keys:

  'response', this will be a HASHREF on success;
  'error', on failure this will be defined, with an error string;

The C<response> hashref will contain various parts of the NTP response packet as outlined in RFC1305.
Like L<Net::NTP> some of the data will be normalised/humanised, such as timestamps are in epoch, NOT hexidecimal.

An example:

          'Root Delay' => '0.001220703125',
          'Version Number' => 3,
          'Precision' => -19,
          'Leap Indicator' => 0,
          'Transmit Timestamp' => '1239808045.86401',
          'Receive Timestamp' => '1239808045.86398',
          'Stratum' => 2,
          'Originate Timestamp' => '1239808045.24414',
          'Reference Timestamp' => '1239807468.92445',
          'Poll Interval' => '0.0000',
          'Reference Clock Identifier' => '193.79.237.14',
          'Mode' => 4,
          'Root Dispersion' => '0.0000'

=head1 AUTHOR

Chris C<BinGOs> Williams <chris@bingosnet.co.uk>

Derived from Net::NTP by James G. Willmore

=head1 LICENSE

Copyright E<copy> Chris Williams and James G. Willmore.

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.

=head1 SEE ALSO

L<Net::NTP>

L<POE>

L<http://www.faqs.org/rfcs/rfc1305.html>

L<http://www.faqs.org/rfcs/rfc2030.html>

=cut
