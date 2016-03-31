#!/usr/bin/perl
use strict;
use warnings;
no warnings 'portable';

use cpu;
use Data::Dumper;

sub mem_read {
    my $cpu = $_[0];
    my @mem = @{$_[1]};
    my ($address, $size, $flags) = ($_[2], $_[3], $_[4]);
    my @retval;

    # print " --== memread called: ", "@_", "\n";

    if ($address + $size > scalar @mem) {
        print " --== returned -1 \n";
        return ($cpu::MEM_ACCESS_PF, [], $address);
    }

    $#retval = $size;
    for (my $i = 0; $i < $size; $i++) {
        $retval[$i] = $mem[$address + $i];
    }

    # print " --== returned @retval \n";

    return (0, \@retval, undef);
}

sub mem_write {
    my $cpu = $_[0];
    my @mem = @{$_[1]};
    my @data = @{$_[3]};
    my ($address, $size, $flags) = ($_[2], $_[4], $_[5]);

    # print " --== memwrite called: $cpu, $@mem, $address, @data, $size, $flags \n";

    if ($address + $size > scalar @mem) {
        print " --== returned -1 \n";
        return ($cpu::MEM_ACCESS_PF, $address);
    }

    for (my $i = 0; $i < $size; $i++) {
        $mem[$address + $i] = $data[$i];
    }

    return (0, undef);
}

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

# &disasm_code(\@code);

my $cpu = new cpu::x64cpu();
my $mem = new cpu::vmem();

if (1) {
    my @ram;
    $#ram = 0xffff;
    for (my $i = 0; $i < scalar @ram; $i++) {
        if ($i >= scalar @code) {
            $ram[$i] = 0;
        }
        else {
            $ram[$i] = $code[$i];
        }
    }

    # $cpu->{user_data} = $mem;
    $cpu->{pl_user_data} = \@ram;

    $cpu->{pl_mem_read} = \&mem_read;
    $cpu->{pl_mem_write} = \&mem_write;

    $cpu->{regs}->{rax} = 0x1234;
    $cpu->{regs}->{rip} = 0x0000;
    $cpu->{regs}->{rsp} = 0xff00;
}
else {
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
}

print "Start: \n";
print cpu::dump($cpu, 1024), "\n\n";

my $running = 1;
while ($running == 1) {
    my $dummycpu = cpu::copy($cpu);
    my ($len, $str) = cpu::disasm_current($dummycpu, 1, 128);

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

