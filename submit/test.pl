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

print $sk "Hello, world!\n";
my $y = <$sk>;
print $y;
close $sk;
