#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "../cpu/cpu.h"
#include "../cpu/disasm.h"
}


uint8_t code[65536];

uint8_t bootloader[] = {
    0x48, 0xBF, /* RDI = offset:  2 */ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xBE, /* RSI = offset: 12 */ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xE8, 0x19, 0x00, 0x00, 0x00, /* Call offset: 25 + 0x19 */
    0xF4, /* HALT */
};

void prime_test_2(int n, int* addr) {
    int* sieve = (addr + 1024 + n); /* Pointer is int size */
    int i, j, c, k = 0;

    for (i = 0; i < n; i++) {
        sieve[i] = 0;
    }

    for (i = 3; i < n; i+=2) {
        sieve[i] = i;
    }

    for (i = 3; i < n; i+=2) {
        if (sieve[i] == 0) {
            continue;
        }

        for (j = 2; j < n; j++) {
            c = i * j;
            if (c >= n) {
                break;
            }
            sieve[c] = 0;
        }
    }

    for (i = 0; i < n; i++) {
        if (sieve[i] != 0) {
            addr[k++] = i;
        }
    }
}

void dummyfn(int n) {
    /* Do not optimize out */
    int i;
    for (i = 0; i < n; i++) {
        code[i] = 0;
    }
}

void prepare_code(int n) {
    uint64_t N = n;
    uint64_t addr = 1024;

    dummyfn(sizeof(code));

    memcpy(&code[0], bootloader, sizeof(bootloader));
    memcpy(&code[50], (void*)prime_test_2, (((char*)dummyfn) - ((char*)prime_test_2)));

    memcpy(&code[2], &N, sizeof(N));
    memcpy(&code[12], &addr, sizeof(addr));
}

void dump_output() {
    uint64_t addr = 1024;
    int len = (sizeof(code) - addr);
    int i, tmp;

    fprintf(stdout, "Result: ");
    for (i = 0; i < len; i++) {
        tmp = *((int*)(&code[addr + (i * sizeof(tmp))]));
        if (tmp == 0) {
            break;
        }

        fprintf(stdout, " %d", tmp);
    }
    fprintf(stdout, "\n");
}

int memory_read(struct x64cpu *cpu, void *user_data, uint64_t address, uint8_t* data, uint8_t size,
                        enum x64cpu_mem_access_flags access_flags, uint64_t *fault_addr) {
    int ret = -1;

    if ((address + size) > sizeof(code)) {
        if (fault_addr) { (*fault_addr) = address; }
        return X64CPU_MEM_ACCESS_PF;
    }

    memcpy(data, &code[address], size);

    return ret;
}

int memory_write(struct x64cpu *cpu, void *user_data, uint64_t address, uint8_t* data, uint8_t size,
                        enum x64cpu_mem_access_flags access_flags, uint64_t *fault_addr) {
    int ret = -1;

    if ((address + size) > sizeof(code)) {
        if (fault_addr) { (*fault_addr) = address; }
        return X64CPU_MEM_ACCESS_PF;
    }

    memcpy(&code[address], data, size);

    return ret;
}



int main(int argc, char **argv) {
    struct x64cpu *cpu;
    int rc;
    char out[128];
    char buffer[4096];

    cpu = x64cpu_create();
    cpu->mem_read = memory_read;
    cpu->mem_write = memory_write;

    prepare_code(100);

    cpu->regs.rip = 0;
    cpu->regs.rsp = sizeof(code) - 8;
    cpu->regs.rbp = cpu->regs.rsp;

    while (1) {
        x64cpu_disasm_current(cpu, (int64_t)0, out, sizeof(out), NULL);
        fprintf(stdout, "0x%016lx: %s\n", cpu->regs.rip, out);

        x64cpu_dump(cpu, buffer, sizeof(buffer));
        fprintf(stdout, "CPU: ");
        fprintf(stdout, "Instructions executed: %ld\n", cpu->instruction_counter);
        fprintf(stdout, "%s\n", buffer);

        rc = x64cpu_execute(cpu);
        if (rc == X64CPU_RES_EXCEPTION) {
            fprintf(stdout, "[*] CPU Exception (%d): [%d] %s at RIP 0x%016lx.\n",
                    cpu->execution_result,
                    cpu->cpu_exception.code, x64cpu_exception_name(cpu->cpu_exception.code),
                    cpu->cpu_exception.rip);
            break;
        }
        else if (rc == X64CPU_RES_SOFTINT) {
            fprintf(stdout, "[*] Unhandled interrupt 0x%02x.\n", cpu->interrupt_number);
            break;
        }
        else if (rc == X64CPU_RES_SYSCALL) {
            fprintf(stdout, "[*] Unhandled syscall\n");
            break;
        }

        if (cpu->is_halted) {
            fprintf(stdout, "[*] CPU Halted.\n");
            break;
        }
    }

    dump_output();

    return 0;
}

