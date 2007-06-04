#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket::INET;
use IO::Socket::SSL; # qw(debug3);

my $sk = new IO::Socket::INET(
#	PeerAddr => "nikam.ms.mff.cuni.cz:443",
	PeerAddr => "localhost:8888",
	Proto => "tcp",
) or die "Cannot connect to server: $!";

my $z = <$sk>;
defined $z or die "Server failed to send welcome message\n";
$z =~ /^\+/ or die "Server reported error: $z";
print $z;

if ($z =~ /TLS/) {
	$sk = IO::Socket::SSL->start_SSL(
		$sk,
		SSL_version => 'TLSv1',
		SSL_use_cert => 1,
		SSL_key_file => "client-key.pem",
		SSL_cert_file => "client-cert.pem",
		SSL_ca_file => "ca-cert.pem",
		SSL_verify_mode => 3,
	) or die "Cannot establish TLS connection: " . IO::Socket::SSL::errstr() . "\n";
}

sub sendobj($) {
	my ($h) = @_;
	foreach my $x (keys %{$h}) {
		print $sk $x, $h->{$x}, "\n";
	}
	print $sk "\n";
	# FIXME: flush
};

sub recvobj() {
	my $h = {};
	while (<$sk>) {
		chomp;
		/^(.)(.*)$/ || last;
		$h->{$1} = $2;
	}
	if (defined $h->{'-'}) { die "-" . $h->{'-'} . "\n"; }
	return $h;
}

sub printobj($) {
	my ($h) = @_;
	foreach my $x (keys %{$h}) {
		print $x, $h->{$x}, "\n";
	}
}

sendobj({ 'U' => 'testuser' });
recvobj();

#sendobj({ '!' => 'SUBMIT', 'T' => 'plans', 'S' => 100, 'X' => 'c' });
#recvobj();
#print $sk "<";
#foreach my $x (1..98) { print $sk "."; }
#print $sk ">";
#recvobj();

sendobj({ '!' => 'STATUS' });
printobj(recvobj());

close $sk;
