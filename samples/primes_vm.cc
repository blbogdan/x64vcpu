#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "../cpu/cpu.h"
#include "../cpu/disasm.h"
#include "../cpu/virtual_memory.h"
}


uint8_t code[128];

uint8_t bootloader[] = {
    0x48, 0xBF, /* RDI = offset:  2 */ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xBE, /* RSI = offset: 12 */ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xB8, /* RAX = 0x08000000 */ 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0, /* CALL EAX */
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

void prepare_code(struct x64cpu_vmem *mem, int n) {
    uint64_t N = n;

    uint64_t boot_addr = 0x4000;

    uint64_t fn_addr = 0x08000000;
    size_t fn_size = (((char*)dummyfn) - ((char*)prime_test_2));
    int fn_page_size = ((fn_size / X64CPU_VMEM_PAGE_SIZE + 1) * X64CPU_VMEM_PAGE_SIZE);

    uint64_t data_addr = 0x09000000;
    uint64_t data_size = 1024 * 1024;

    size_t i;

    dummyfn(sizeof(code));

    x64cpu_vmem_map(mem, boot_addr, 0x1000, X64CPU_VMEM_PAGE_FLAG_RW | X64CPU_VMEM_PAGE_FLAG_U | X64CPU_VMEM_PAGE_FLAG_P, NULL, 1);
    for (i = 0; i < sizeof(bootloader); i++) {
        x64cpu_vmem_write(mem, (boot_addr + i), (uint8_t*)&bootloader[i], sizeof(char), 0, NULL);
    }

    /* Write (int n, int * addr) parameters */
    x64cpu_vmem_write(mem, (boot_addr + 2), (uint8_t*)&N, sizeof(N), 0, NULL);
    x64cpu_vmem_write(mem, (boot_addr + 12), (uint8_t*)&data_addr, sizeof(data_addr), 0, NULL);

    /* Write function */
    if (x64cpu_vmem_map(mem, fn_addr, fn_page_size, X64CPU_VMEM_PAGE_FLAG_RW | X64CPU_VMEM_PAGE_FLAG_U | X64CPU_VMEM_PAGE_FLAG_P, NULL, 1) != 1) {
        fprintf(stderr, "Cannot map page %lx / %lx\n", fn_addr, fn_page_size);
        return;
    }
    x64cpu_vmem_copyto(mem, fn_addr, (void*)prime_test_2, fn_size);

    /* Map data section */
    x64cpu_vmem_map(mem, data_addr, data_size, X64CPU_VMEM_PAGE_FLAG_RW | X64CPU_VMEM_PAGE_FLAG_U | X64CPU_VMEM_PAGE_FLAG_P, NULL, 1);
}

void dump_output(struct x64cpu_vmem *mem) {
    uint64_t data_addr = 0x09000000;
    uint64_t data_size = 1024 * 1024;
    uint8_t *buf = malloc(data_size);
    int i, tmp;

    x64cpu_vmem_copyfrom(mem, data_addr, buf, data_size);

    fprintf(stdout, "Result: ");
    for (i = 0; i < data_size / sizeof(int); i++) {
        tmp = ((int*)buf)[i];
        if (tmp == 0) {
            break;
        }

        fprintf(stdout, " %d", tmp);
    }
    fprintf(stdout, "\n");
}

int main(int argc, char **argv) {
    struct x64cpu *cpu;
    struct x64cpu_vmem mem;
    int rc;
    char out[128];
    char buffer[4096];

    cpu = x64cpu_create();
    cpu->user_data = (void*)&mem;
    cpu->mem_read = x64cpu_vmem_read_cpu_glue;
    cpu->mem_write = x64cpu_vmem_write_cpu_glue;

    prepare_code(&mem, 10000);

    cpu->regs.rip = 0x4000;

    int stack_size = 1024 * 1024;
    int stack_base_addr = 0x77ffffff;
    int stack_top_addr = stack_base_addr - stack_size + 0x1000;
    x64cpu_vmem_map(&mem, stack_top_addr, stack_size, X64CPU_VMEM_PAGE_FLAG_RW | X64CPU_VMEM_PAGE_FLAG_U | X64CPU_VMEM_PAGE_FLAG_P, NULL, 1);
    cpu->regs.rsp = stack_base_addr - 8;
    cpu->regs.rbp = cpu->regs.rsp;

    while (1) {
#if 0
        x64cpu_disasm_current(cpu, (int64_t)0, out, sizeof(out), NULL);
        fprintf(stdout, "0x%016lx: %s\n", cpu->regs.rip, out);

        x64cpu_dump(cpu, buffer, sizeof(buffer));
        fprintf(stdout, "CPU: ");
        fprintf(stdout, "Instructions executed: %ld\n", cpu->instruction_counter);
        fprintf(stdout, "%s\n", buffer);
#endif

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

    fprintf(stdout, "Instructions executed: %ld.\n", cpu->instruction_counter);

    dump_output(&mem);

    return 0;
}

