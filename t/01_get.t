use strict;
use warnings;
use Test::More tests => 16;
use POE qw(Component::Client::NTP);

my @fields = (
 'Root Delay',
 'Version Number',
 'Precision',
 'Leap Indicator',
 'Transmit Timestamp',
 'Receive Timestamp',
 'Stratum',
 'Originate Timestamp',
 'Reference Timestamp',
 'Poll Interval',
 'Reference Clock Identifier',
 'Mode',
 'Root Dispersion'
);

POE::Session->create(
  package_states => [
	main => [qw(_start _stop _response)],
  ],
);

$poe_kernel->run();
exit 0;

sub _start {
  POE::Component::Client::NTP->get_ntp_response(
     host => 'pool.ntp.org',
     event => '_response',
  );
  return;
}

sub _stop {
  pass('Refcount was decremented');
  return;
}


sub _response {
  my $packet = $_[ARG0];
  ok( $packet->{response}, 'There is a response' );
  is( ref $packet->{response}, 'HASH', 'And the response is a HASHREF' );
  ok( defined $packet->{response}->{ $_ }, $_ ) for @fields;
  return;
}
