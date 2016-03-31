#!/usr/bin/perl
use strict;
use warnings;
no warnings 'portable';

use cpu;

sub disasm_code {
    my @code = @{$_[0]};
    my ($len, $str, $codes, $vrip, $out);
    my @ptr;

    $vrip = 0;
    while ($vrip < scalar @code) {
        @ptr = (@code[$vrip..$#code], 0x90, 0x90);
        ($len, $str) = cpu::disasm(\@ptr, $vrip, 1, 128, undef);

        @ptr = @code[$vrip..($vrip + $len - 1)];
        $out = "";
        for (my $i = 0; $i < scalar @ptr; $i++) {
            $out = $out . sprintf("%02x ", $ptr[$i]);
        }

        print sprintf ("%016x:    %-30s %s\n", $vrip, $out, $str);
        $vrip += $len;
    }
}

my @code = (0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69
          , 0x6e, 0x89, 0xe3, 0x50, 0x53, 0x89, 0xe1, 0xb0, 0x0b, 0xcd, 0x80);

&disasm_code(\@code);

my $cpu = new cpu::x64cpu();
my $mem = new cpu::vmem();

$cpu->{user_data} = $mem;
$cpu->{pl_mem_read} = $cpu::vmem_read_cpu_glue_cb;
$cpu->{pl_mem_write} = $cpu::vmem_write_cpu_glue_cb;

cpu::vmem_map($mem, 0xf000, 0x2000, 
        $cpu::VMEM_PAGE_FLAG_RW | $cpu::VMEM_PAGE_FLAG_U | $cpu::VMEM_PAGE_FLAG_P, undef, 1);

my $addr = 0xf000;
for (my $i = 0; $i < scalar @code; $i++) {
    my $rc = cpu::vmem_write_uint8_t($mem, $addr, $code[$i], 0, undef);
    if ($rc != $cpu::MEM_ACCESS_SUCCESS) {
        print sprintf("Error writing memory at 0x%016x\n", $addr);
    }
    $addr += 1;
}

$cpu->{regs}->{rax} = 0x1234;
$cpu->{regs}->{rip} = 0xf000;
$cpu->{regs}->{rsp} = 0xf000 + 0x2000;

print "Start: \n";
print cpu::dump($cpu, 1024), "\n\n";

my $running = 1;
while ($running == 1) {
    my ($len, $str) = cpu::disasm_current($cpu, 1, 128);
    $cpu->{regs}->{rip} -= $len;

    my $rc = cpu::execute($cpu);

    print "\t$str\n";
    print cpu::dump($cpu, 1024), "\n";

    if ($rc == $cpu::RES_EXCEPTION) {
        print "Exception: ", cpu::exception_name($cpu->{cpu_exception}->{code}), "\n";
    }
    elsif ($rc == $cpu::RES_SYSCALL) {
        print sprintf("Syscall: 0x%x", $cpu->{regs}->{rax}), "\n";
    }
    elsif ($rc == $cpu::RES_SOFTINT) {
        print sprintf("Interrupt: 0x%02x", $cpu->{interrupt_number}), "\n";
    }

    if ($cpu->{is_halted} != 0 || $rc != 0) {
        $running = 0;
    }
}

print "Done.\n";

