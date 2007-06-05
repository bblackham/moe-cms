#!/usr/bin/perl

use strict;
use warnings;

use lib ".";
use lib "lib/perl5";

use MO::Submit;
use Sherlock::Object;

my $conn = new MO::Submit;
$conn->connect or die;

#$req = new Sherlock::Object;
#$req->set("!" => "SUBMIT", "T" => "plans", "X" => "pas", "S" => 100);
#req($req);
#$reply = reply();
#print $sk "<..................................................................................................>";
#$reply = reply();

my $r = new Sherlock::Object("!" => "STATUS");
$r = $conn->request($r) or die;
$r->write_indented(*STDOUT);

$conn->disconnect;
