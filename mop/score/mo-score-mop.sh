#!/usr/bin/perl

$tex = 0;
$usage = "Usage: mo-score-mop [--tex] theoretical_tasks_nr praxis_tasks_nr task1 task2 ...";
while (($arg = $ARGV[0]) =~ /^--([a-z]+)$/) {
	shift @ARGV;
	$var = "\$$1";
	if (!eval "defined $var") { die $usage; }
	eval "$var = 1;";
}
@ARGV >=2 || die $usage;
$theory=shift @ARGV;
$praxis=shift @ARGV;
@ARGV >= $praxis || die $usage;
$pos_delim=$tex ? '--' : '-';

print STDERR "Scanning contestants... ";
open (CT, "bin/mo-get-users --full |") || die "Cannot get list of contestants";
while (<CT>) {
	chomp;
	($u,$f) = split /\t/;
	($u eq "somebody") && next;
        $users{$u}=$f;
}
close CT;
print STDERR 0+keys %users, "\n";

print STDERR "Scanning teoretical results... ";
if (open (EX, "mop/score/teorie.txt")) {
	while (<EX>) {
		chomp;
		(/^$/ || /^#/) && next;
		@a = split /\ *\t\ */;
		$u = shift @a;
		defined $users{$u} || die "Unknown user $u";
		$names{$u} = shift @a;
		$forms{$u} = shift @a;
		$addresses{$u} = "{". (shift @a) ."}";
		$i=0;
		while (@a) { $tasks{$u}{$i} = shift @a;$i++; }
	}
	close EX;
	print STDERR "OK\n";
} else {die "none, cannot find file teorie.txt!\n";}

print STDERR "Scanning task results... ";
$need_tasks = join("|", @ARGV);
foreach $u (keys %users) {
	opendir (D, "testing/$u") or next;
	foreach $t (readdir(D)) {
		$t =~ /^\./ && next;
		$t =~ /$need_tasks/ || next;

		$t_num=$praxis;
		for (my $t_num2=0;$t_num2<@ARGV;$t_num2++) {if ($t eq $ARGV[$t_num2]) {$t_num=$t_num2;}}
		$t_num+=$theory;

		$tt = "testing/$u/$t/points";
		-f $tt || next;
		print STDERR "$u/$t ";
		open (X, $tt) || die "Unable to open $tt";

                my %tests = ();
		while (<X>) {
			chomp;
			/^(\S+) (-?\d+)/ || die "Parse error: $_";
                        my ($t, $p) = ($1, $2);
                        $t =~ s/[^0-9]//g;
			$tests{$t} = $p if not exists $tests{$t} or $tests{$t} > $p;
		}
		foreach my $p (values %tests) {
			$tasks{$u}{$t_num} += $p;
		}
		close X;
	}
	closedir D;
}
print STDERR "OK\n";

print STDERR "Creating table template... ";
@body = ('','$names{$u}','$forms{$u}','$addresses{$u}');
for ($a=0;$a<$theory+$praxis;$a++) {push @body,"\$tasks{\$u}{$a}";}
print STDERR "OK\n";

print STDERR "Filling in results... ";
@table = ();
foreach $u (keys %users) {
	next unless defined $names{$u}; # don't show any user not defined in teorie.txt
	$row = [];
	$row_index=0;
	$row_sum=0;
	foreach my $c (@body) {
		$c =~ s/\$(\d+)/\$\$row[$1]/g;
		$x = eval $c;
		push @$row, (defined $x ? $x : '-');
		if ($row_index>3) {
		    if ((defined $x) && ($x>0)) {$row_sum+=$x;}
		}
		$row_index++;
	}
	push @$row, $row_sum;
	push @table, $row;
}
print STDERR "OK\n";

print STDERR "Sorting... ";
$sortcol = @{$table[0]} - 1;
$namecol = 1;
@table = sort {
	my $p, $an, $bn;
	$p = $$b[$sortcol] <=> $$a[$sortcol];
	($an = $$a[$namecol]) =~ s/(\S+)\s+(\S+)/$2 $1/;
	($bn = $$b[$namecol]) =~ s/(\S+)\s+(\S+)/$2 $1/;
	$p ? $p : ($an cmp $bn);
} @table;
$i=0;
while ($i < @table) {
	$j = $i;
	while ($i < @table && ${$table[$i]}[$sortcol] == ${$table[$j]}[$sortcol]) {
		$i++;
	}
	if ($i == $j+1) {
		${table[$j]}[0] = "$i.";
	} else {
		${table[$j]}[0] = $j+1 . '.' . $pos_delim . $i . ".";
		$j_old=$j;
		$j++;
		while ($j < $i) { ${table[$j++]}[0] = $j_old+1 . '.' . $pos_delim . $i . "."; };
	}
}
print STDERR "OK\n";

if ($tex) {
        open HDR,"mop/score/listina.hdr" or die "Cannot open file mop/score/listina.hdr with TeX template!";
	while (<HDR>) {print; }
	close HDR;
	
	foreach $r (@table) { print join('&',@$r), "\\cr\n";}

        open FTR,"mop/score/listina.ftr" or die "Cannot open file mop/score/listina.ftr with TeX template!";
	while (<FTR>) {print; }
	close FTR;
} else {
	foreach $r (@table) { print join("\t",@$r), "\n"; }
}
