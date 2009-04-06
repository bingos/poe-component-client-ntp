use strict;
use warnings;
use Test::More tests => 1;
use POE qw(Component::Client::NTP);
use Data::Dumper;

POE::Session->create(
  package_states => [
	main => [qw(_start _stop _response)],
  ],
);

$poe_kernel->run();
exit 0;

sub _start {
  POE::Component::Client::NTP->get_ntp_response(
     host => 'uk.pool.ntp.org',
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
  diag(Dumper($_[ARG0]));
  return;
}
