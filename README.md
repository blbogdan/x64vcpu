x64vcpu - 64-bit x86 CPU Emulator
=================================

!!! STILL IN DEVELOPMENT - Features might be missing. Library interface
and function prototypes might (WILL) change. !!!

x64vcpu is a small library written in C offering 64-bit x86 emulation and
sandboxing geared more towards userspace code emulation. It is meant to
provide the means of safely executing untrusted code and/or analyzing it.

The emulator works by decoding the instruction and then executing it. You
can inspect the decoded instruction before it is executed and analyzing it
or just use it to decode instructions without executing any.
The included disassembler is built this way.

It also includes a primitive component that loads ELF binaries and executes
them in a sandbox by intercepting and emulating syscalls.

The library is still in development. It might include the following
limitations:
* Missing 32-bit opcodes and emulation
* Some missing opcodes
* Few FPU opcodes implemented
* Few SSE/SSE2 opcodes implemented
* Missing Page protection, yet
* Missing NX bit
* Only 64-bit userspace emulated
* BUGS


License
------------

Licensed under GNU LGPL version 3. See LICENSE for details.

Compilation
------------

Grab the code from the repository:
```bash
git clone <url>
```
Note: The "master" branch is considered stable (meaning "at least it
compiles"), but expect interface changes.
The "experimental" branch might contain random improvements that might even
not compile.

Use cmake to build the makefiles:
```bash
cmake .
```

Compilation:
```bash
make <target> # empty builds all
```

Targets:
- x64cpu - The CPU library and disassembler
- environment - The environment for ELF binaries emulation
- pedumper - Sample PE dumper with disassembler
- primes - Sample usage of x64cpu
- primes_vm - Sample usage of x64cpu with pagging memory
- linload - Sample ELF binary emulation using the "environment" library
- emudbg - Experimental debugger using the "environment" library
- cpu | env - x64cpu and environment Perl wrappers
- test03..06 - Test binaries to be loaded by the library for testing


