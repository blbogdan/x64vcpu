#include <stdio.h>
#include <stdlib.h>


int main(int argc, char **argv) {
    float a, b, c;
    __float80 x, y, z;
    char *d;
    int i;

    a = 24.0;
    b = 5.0;
    c = a / b;

    printf("Result: %9.9f\n", c);

    d = ((char*)&c);

    for (i = 0; i < sizeof(c); i++) {
        fprintf(stdout, "%02x ", d[i]);
    }
    fprintf(stdout, "\n");

    x = 127.0;
    y = 11;
    z = x / y;
    z *= c;

    fprintf(stdout, "%Lf", z);

    return 0;
}

