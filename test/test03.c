
void prime_test_2(int n, int* addr);

int data[1 * 1024 * 1024];

void _start() {
    prime_test_2(500, data);
    __asm__ __volatile__("hlt");
}

void prime_test_2(int n, int* addr) {
    int* sieve = (addr + 1024 + n); /* Pointer is int size */
    unsigned int i, j, c, k = 0;

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

