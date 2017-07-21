// RSA signature decryption, compile with -DPOC to build an executable
// proof-of-concept (the POC code can be removed in production).

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "unsign.h"

// The "bignum" array type, note passed by reference in all cases.
#define BNWORDS ((UNSIGNMAX/4)+1)
typedef uint32_t BN[BNWORDS];

#ifdef POC
static void debug(char *before, BN a, char *after);
#else
#define debug(...)
#endif

// true if specified bit 0 to UNSIGNBITS+31 (LSB to MSB) is set in BN
#define bit(a,i) (a[i/32] & (1<<(i&31)))

// a = 0
#define clr(a) memset(a,0,sizeof(BN))

// a = b
#define set(a,b) memcpy(a,b,sizeof(BN))

// a = n, where n is 32-bit numeric
#define setn(a,n) clr(a),a[0]=n

// Return index of most signifcant bit set in the BN, 0 to UNSIGNBITS+31, or -1
// if none. bit(msb(a)) will always be true for a non-zero BN.
static int msb(BN a)
{
    int i, j;

    for (i=BNWORDS-1; i >= 0; i--)
        if (a[i])
            for(j=31; j >= 0; j--)
                if (a[i] & 1<<j)
                    return i*32+j;
    return -1;
}

// a <<= 1
static void shl(BN a)
{
    int i, carry=0;

    for (i=0; i<BNWORDS; i++)
    {
        int c=a[i] >= 0x80000000;
        a[i]=(a[i] << 1) | carry;
        carry=c;
    }
}

// a += b
static void add(BN a, BN b)
{
    int i, carry=0;

    for (i=0; i < BNWORDS; i++)
    {
        uint32_t n = a[i]+b[i]+carry;
        carry = carry ? n <= a[i] : n < a[i];
        a[i]=n;
    }
}

// a -= b
static void sub(BN a, BN b)
{
    int i, borrow=0;

    for (i=0; i<BNWORDS; i++)
    {
        uint32_t n = a[i]-b[i]-borrow;
        borrow=borrow ? a[i] <= b[i] : a[i] < b[i];
        a[i]=n;
    }
}

// compare a to b, return 0 if a==b, 1 if a>b, -1 if a<b
static int cmp(BN a, BN b)
{
    int i;

    for(i=BNWORDS-1; i>=0; i--)
    {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// a = ( a * b ) mod m
static void mulmod(BN a, BN b, BN m)
{
    int i, h;
    BN r;

    clr(r);                             // r=0

    h=msb(b);                           // get most significant set bit
    for (i=0; i<=h; i++)                // for each bit in b
    {
        if (bit(b,i))                   // if it's set
        {
            add(r,a);                   // then r += a
            if (cmp(r,m)>=0) sub(r,m);  // modulo m
        }
        shl(a);                         // a*=2
        if (cmp(a,m)>=0) sub(a,m);      // modulo m
    }

    // return result in a
    set(a,r);
}

// a = (a ^ b) mod m
static void expmod(BN a, BN b, BN m)
{
    int i, h;
    BN r;

    setn(r,1);                          // r=1

    h=msb(b);                           // get most significant set bit
    for (i=0; i<=h; i++)                // for each bit in b
    {
        BN temp;
        if (bit(b,i)) mulmod(r,a,m);    // if set then r = (r*a) mod m
        set(temp, a);                   // a=(a^2) mod m
        mulmod(a,temp,m);
    }

    // return result in a
    set(a,r);
}

// Given an BN and a pointer to data array of specified size, pack the
// big-endian array into the little-endian BN and return 0. Return -1 if
// array size is too big for an BN.
static int pack(BN a, uint8_t *data, int size)
{
    int n, i;

    if (size > UNSIGNMAX) return -1;

    clr(a);
    for (n=0, i=size-1; n<size; n++, i--) a[i/4] |= data[n] << ((i&3)*8);
    return 0;
}

// Given an BN, and a pointer to data array of specified size, unpack the
// little-endian BN into the big-endian array and return 0. Return -1 if array
// size is too small to contain the BN (ignoring leading 0x00's).
static int unpack(BN a, uint8_t *data, int size)
{
    int n, i;

    if (size > UNSIGNMAX || msb(a) >= size*8) return -1;

    for (n=0, i=size-1; n<size; n++, i--) data[n] = a[i/4] >> ((i&3)*8);

    return 0;
}

// Given a BN and a hexstring, unpack the big-endian string into
// little-endian BN and return 0. Return -1 if string is invalid or too
// long to fit into an BN.
static int load(BN a, const char *s)
{
    int size=strlen(s), n, i;
    if (size > UNSIGNMAX*2) return -1;  // string too long

    clr(a);
    for (n=0, i=size-1; n < size; n++, i--)
    {
        int d;
        // unhex
        if (s[n] >= '0' && s[n] <= '9') d=s[n]-'0';
        else if (s[n] >= 'A' && s[n] <= 'F') d=s[n]-'A'+10;
        else if (s[n] >= 'a' && s[n] <= 'f') d=s[n]-'a'+10;
        else return -1; // bzzt
        a[i/8] |= d << ((i&7)*4);
    }
    return 0;
}

// Given a pointer to an openssl RSA signature blob, size in bytes, and a hex
// modulus string, decrypt the blob in place and return 0. This does not remove
// PKCS#1 padding, if any. Non-zero indicates some error.
int unsign(uint8_t *blob, int size, char *modulus)
{
    BN sig, e, mod;

    if (pack(sig, blob, size)) return -1;   // pack the blob into the bignum, fail if too big
    debug("sig=",sig,"\n");
    if (load(mod,modulus)) return -2;       // load the modulus string, fail if non-hex or whatever
    debug("mod=",mod,"\n");
    if (cmp(sig,mod)>=0) return -3;         // fail if signature not less than modulus
    setn(e,65537);                          // set openssl's static exponent
    expmod(sig, e, mod);                    // do the math
    if (unpack(sig,blob,size)) return -4;   // unpack the bignum back into the array, fail if too big (shouldn't happen)
    debug("out=",sig,"\n");
    return 0;
}

#ifdef POC
// Proof-of-concept and various test cases enabled by -DMULMOD or whatever.

// Die with a message
#define die(...) fprintf(stderr, __VA_ARGS__), exit(1)

// Print a BN with optional wrapper text
static void debug(char *before, BN a, char *after)
{
    int n;
    if (before) fprintf(stderr,"%s", before);
    for (n=BNWORDS-1; n>0; n--) if(a[n]) break; // skip leading zeros
    fprintf(stderr,"%X", a[n]);
    for (n--; n>=0; n--) fprintf(stderr, "%08X", a[n]);
    if (after) fprintf(stderr,"%s", after);
}

int main(int argc, char *argv[])
{
#if defined(ADD)
    BN a, b;
    if (argc != 3) die("Usage: %s a b, reports a+b\n", argv[0]);

    if (load(a, argv[1])) die("Failed to load a, invalid or too long?\n");
    if (load(b, argv[2])) die("Failed to load b, invalid or too long?\n");
    debug("a=", a, "\n");
    debug("b=", b, "\n");
    add(a,b);
    debug("r=",a,"\n");
#elif defined(SUB)
    BN a, b;
    if (argc != 3) die("Usage: %s a b, reports a-b\n", argv[0]);

    if (load(a, argv[1])) die("Failed to load a, invalid or too long?\n");
    if (load(b, argv[2])) die("Failed to load b, invalid or too long?\n");
    debug("a=", a, "\n");
    debug("b=", b, "\n");
    sub(a,b);
    debug("r=",a,"\n");
#elif defined(MULMOD)
    BN a, b, m;
    if (argc != 4) die("Usage: %s a b m, reports a*b%%m -- a and b MUST be less than m!\n", argv[0]);

    if (load(a, argv[1])) die("Failed to load a, invalid or too long?\n");
    if (load(b, argv[2])) die("Failed to load b, invalid or too long?\n");
    if (load(m, argv[3])) die("Failed to load m, invalid or too long?\n");
    debug("a=", a, "\n");
    debug("b=", b, "\n");
    debug("m=", m, "\n");
    mulmod(a,b,m);
    debug("r=",a,"\n");
#elif defined(EXPMOD)
    // expmod test
    BN a, b, m;
    if (argc != 4) die("Usage: %s a b m, reports a^b%%m -- a and b MUST be less than m!\n", argv[0]);

    if (load(a, argv[1])) die("Failed to load a, invalid or too long?\n");
    if (load(b, argv[2])) die("Failed to load b, invalid or too long?\n");
    if (load(m, argv[3])) die("Failed to load m, invalid or too long?\n");
    debug("a=", a, "\n");
    debug("b=", b, "\n");
    debug("m=", m, "\n");
    expmod(a,b,m);
    debug("r=",a,"\n");
#else
    // echo hello | openssl rsautl -sign -inkey private.key | ./unsign $(openssl x509 -modulus -noout < public.cert | awk '{print $2}' FS==)
    // (note this example will output PKCS#1 padding added by openssl, followed by 'hello')
    int size, err;
    uint8_t blob[UNSIGNMAX+1]; // allow reading too many bytes

    if (argc != 2) die("Usage: %s modulus < signature > data\n", argv[0]);

    // read signature data from stdin
    size=read(0, &blob, sizeof(blob));
    if (size <= 0) die("Error reading stdin\n");

    err=unsign(blob,size,argv[1]);
    if (err) switch (err)
    {
        case -1: die("Failed to pack signature, too much input?\n"); break;
        case -2: die("Failed to load modulus, invalid or too long?\n"); break;
        case -3: die("Signature is not less than modulus\n"); break;
        case -4: die("Failed to unpack decrypted signature?!?\n"); break;
        default: die("Unknown error %d\n", err);
    }

    // write the decrypted blob
    write(1, blob, size);
#endif
}
#endif
