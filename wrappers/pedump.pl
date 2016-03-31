#!/usr/bin/perl
use strict;
use warnings;
no warnings 'portable';

use cpu;
use env;

my $pe;
my $pe_filename;

my $num_args = $#ARGV + 1;
if ($num_args < 1) {
    print "\nUsage: envtest.pl <filename>\n";
    exit;
}

$pe_filename = $ARGV[0];

open FILE, $pe_filename or die "Couldn't open $pe_filename: $!";
binmode FILE;

sub pe_read {
    my $op = $_[0];
    my $ud = $_[1];
    my $n = $_[2];
    my $rc = -1;

    if ($op == $env::PEFile::IO_CB_OP_SEEK) {
        $rc = seek(FILE, $n, 0);
        $rc = ($rc == 1) ? 0 : -$!;
        return ($rc, undef);
    }
    elsif ($op == $env::PEFile::IO_CB_OP_READ) {
        my $buf = undef;
        $rc = read(FILE, $buf, $n);
        $rc = (defined $rc) ? $rc : -$!;
        return ($rc, $buf);
    }

    return (-1, undef);
}

$pe = env::PEFile::loadPE($pe_filename, \&pe_read);

print $pe, "\n";
print $pe->dump();

print $pe->{coff_header};

