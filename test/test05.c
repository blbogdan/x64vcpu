#include <stdio.h>
#include <stdlib.h>

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

int main(int argc, char **argv) {
    printf("Hello, world!\n");

	int n = 100;
	int *buffer = malloc(sizeof(int) * 4 * 1024 * 1024);

    if (buffer == NULL) {
        fprintf(stderr, "Error allocating memory!\n");
        return 1;
    }

    printf("Allocated!\n");

	prime_test_2(n, buffer);

	int i;
	for (i = 0; i < n; i++) {
		if (buffer[i] == 0) { break; }
		printf("%d ", buffer[i]);
	}

    // free(buffer);

    return 0;
}

