// unsign.h

#include <inttypes.h>

// Largest supported openssl key, must be multiple of 32. Smaller keys are
// allowed.
#define UNSIGNBITS 4096

// Given a pointer to an openssl RSA signature blob, size in bytes, and a hex
// modulus string, decrypt the blob in place and return 0. This does not remove
// PKCS#1 padding, if any. Non-zero indicates some error.
int unsign(uint8_t *blob, int size, char *modulus);
