// unsign test code, decrypt any RSA signature up to UNSIGNSIZE * 8 bits
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "unsign.h"

#define die(...) fprintf(stderr, __VA_ARGS__), exit(1)

int main(int argc, char *argv[])
{
    int size, err;
    uint8_t blob[(UNSIGNBITS / 8) + 1]; // allow reading too many bytes, so we can fail on oversize input

    if (argc != 2) die("Usage: %s modulus < signature > data\n", argv[0]);

    // read signature data from stdin
    size = read(0, &blob, sizeof(blob));
    if (size <= 0) die("Error reading stdin\n");

    err = unsign(blob, size, argv[1]);
    if (err) switch (err)
    {
        case -1: die("Failed to pack signature, too much input?\n"); break;
        case -2: die("Failed to load modulus, invalid or too long?\n"); break;
        case -3: die("Signature is not less than modulus\n"); break;
        case -4: die("Failed to unpack decrypted signature?!?\n"); break;
        default: die("Unknown error %d\n", err);
    }

    // Write the decrypted blob.
    // If the wrong key was supplied then we'll output garbage here.
    write(1, blob, size);

    return 0;
}
