#!/usr/bin/perl
use strict;
use warnings;
no warnings 'portable';

use cpu;
use env;

my $rc;
my $elf;

my $env = new env::EnvLinux();

my $proc = $env->createProcess();

$rc = env::ElfLoader->loadElfFromFile("../test05", $elf);

print $rc , $elf;

