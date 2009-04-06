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

  return;
}

sub _timeout {
}

sub _get_datagram {
  my ($kernel,$self,$socket) = @_[KERNEL,OBJECT,ARG0];
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
