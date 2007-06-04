#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket::INET;
use IO::Socket::SSL; # qw(debug3);

use lib "lib/perl5";
use Sherlock::Object;

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

sub req($) {
	my $x = shift @_;
	$x->write($sk);
	print $sk "\n";
}

sub reply() {
	my $x = new Sherlock::Object;
	$x->read($sk) or die "Incomplete reply";
	$x->get('+') or die "-" . $x->get('-') . "\n";
	return $x;
}

my $req;
my $reply;

$req = new Sherlock::Object;
$req->set("U" => "testuser");
req($req);
$reply = reply();

#$req = new Sherlock::Object;
#$req->set("!" => "SUBMIT", "T" => "plans", "X" => "pas", "S" => 100);
#req($req);
#$reply = reply();
#print $sk "<..................................................................................................>";
#$reply = reply();

$req = new Sherlock::Object;
$req->set("!" => "STATUS");
req($req);
$reply = reply();
$reply->write_indented(*STDOUT);

close $sk;
