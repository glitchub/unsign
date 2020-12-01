// unsign.h

#include <inttypes.h>

// Largest supported openssl key size in bits, must be power of 2.
#define UNSIGNBITS 4096

// Given a pointer to an openssl RSA signature blob, size in bytes, and a hex
// modulus string, decrypt the blob in place and return 0. This does not remove
// PKCS#1 padding, if any. Various non-zero responses indicate an error, e.g.
// size > UNSIGNMAX.
int unsign(uint8_t *blob, int size, char *modulus);
