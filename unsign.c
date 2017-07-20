// RSA signature decryption, compile with -DPOC to build an executable
// proof-of-concept

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "unsign.h"

// bytes in longest supported key
#define KBYTES ((UNSIGNBITS)/8)   

// we only need one additional bit but have to allocate another word
#define BNWORDS ((UNSIGNBITS/32)+1) 

// "Bignum" array type, passed by reference in all cases.
typedef uint32_t BN[BNWORDS];

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

    for (i=0; i < BNWORDS; i++)
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
        uint64_t n = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        a[i]=n & 0xffffffff;
        carry = n > 0xffffffff;
    }
}

// a -= b
static void sub(BN a, BN b)
{
    int i, carry=0;

    for (i=0; i < BNWORDS; i++) 
    {
        uint64_t n = (uint64_t)a[i] - (uint64_t)b[i] - carry;
        a[i]=n & 0xffffffff;
        carry = n > 0xffffffff;
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
            if (cmp(r,m)>=0) sub(r,m);  // keep r in range
        }
        shl(a);                         // a*=2
        if (cmp(a,m)>=0) sub(a,m);      // keep a in range
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
    int n;

    if (size > KBYTES) return -1;
    
    clr(a);
    for (n=0; n<size; n++) 
    {
        int d=data[n];
        switch ((size-1-n) & 3)
        {
            case 3: d <<= 24; break; 
            case 2: d <<= 16; break; 
            case 1: d <<= 8; break; 
        }
        a[(size-1-n)/4] |= d;;
    }
    return 0;
}    

// Given an BN, and a pointer to data array of specified size, unpack the
// little-endian BN into the big-endian array and return 0. Return -1 if array
// size is too small to contain the BN (ignoring leading 0x00's).
static int unpack(BN a, uint8_t *data, int size)
{
    int n;

    if (size > KBYTES || msb(a) >= size*8) return -1;

    for (n=0; n<size; n++) 
    {
        int d=a[(size-1-n)/4];
        switch((size-1-n) & 3)
        {
            case 3: d >>= 24; break;
            case 2: d >>= 16; break;
            case 1: d >>= 8; break;
        }    
        data[n]=d;
    }

    return 0;
}    

// Given a BN and a hexstring, unpack the big-endian string into
// little-endian BN and return 0. Return -1 if string is invalid or too
// long to fit into an BN.
static int load(BN a, const char *s)
{
    int size=strlen(s), n;

    if (size > KBYTES*2) return -1;

    clr(a);
    for (n=0; n < size; n++)
    {
        int d;
        if (s[n] >= '0' && s[n] <= '9') d=s[n]-'0';
        else if (s[n] >= 'A' && s[n] <= 'F') d=s[n]-'A'+10;
        else if (s[n] >= 'a' && s[n] <= 'f') d=s[n]-'a'+10;
        else return -1; // invalid hex
        switch((size-1-n) & 7)
        {
            case 7: d <<= 28; break;
            case 6: d <<= 24; break;
            case 5: d <<= 20; break;
            case 4: d <<= 16; break;
            case 3: d <<= 12; break;
            case 2: d <<= 8; break;
            case 1: d <<= 4; break;
        }
        a[(size-1-n)/8] |= d;
    }   
    return 0;
}

#ifdef POC
static void debug(char *before, BN a, char *after);
#else
#define debug(...)
#endif

// Given a pointer to an openssl RSA signature blob, size in bytes, and a hex
// modulus string, decrypt the blob in place and return 0. This does not remove
// PKCS#1 padding, if any. Non-zero indicates some error.
int unsign(uint8_t *blob, int size, char *modulus)
{
    BN sig, e, mod;

    if (pack(sig, blob, size)) return -1;   // pack the blob into the bignum
    debug("sig=",sig,"\n"); 
    if (load(mod,modulus)) return -2;       // load the modulus string    
    debug("mod=",mod,"\n");
    if (cmp(sig,mod)>=0) return -3;         // signature must be less than modulus
    setn(e,65537);                          // set openssl's static exponent
    expmod(sig, e, mod);                    // do the math
    if (unpack(sig,blob,size)) return -4;   // unpack the bignum back into the array
    debug("out=",sig,"\n");
    return 0;
}

#ifdef POC

// die with a message
#define die(...) fprintf(stderr, __VA_ARGS__), exit(1)

// print a BN with optional wrapper text
static void debug(char *before, BN a, char *after)
{
    int n;
    if (before) fprintf(stderr,"%s", before);
    for (n=BNWORDS-1; n>0; n--) if(a[n]) break; // skip leading zeros
    fprintf(stderr,"%X", a[n]);   
    for (n--; n>=0; n--) fprintf(stderr, "%08X", a[n]);
    if (after) fprintf(stderr,"%s", after);
}

#ifdef EXPMOD
// expmod test 
// ./unsign 123 345 12345 performs 123 ^ 345 % 12345 == C720
int main(int argc, char *argv[])
{
    BN a, b, m;
    if (argc != 4) die("Usage: a b mod\n");

    if (load(a, argv[1])) die("Failed to load a, odd length?\n");
    if (load(b, argv[2])) die("Failed to load b, odd length?\n");
    if (load(m, argv[3])) die("Failed to load m, odd length?\n");
    debug("a=", a, "\n");
    debug("b=", b, "\n");
    debug("m=", m, "\n");
    expmod(a,b,m);
    debug("r=",a,"\n");
}
#else
// unsign test
// echo hello | openssl rsautl -sign -inkey private.key | ./unsign $(openssl x509 -modulus -noout < public.cert | awk '{print $2}' FS==)
// (note this example will output PKCS#1 padding added by openssl, ending with 'hello')
int main(int argc, char *argv[])
{
    int size, err;
    uint8_t blob[KBYTES+1]; // allow reading too many bytes
    
    if (argc != 2) die("Usage: unsign modulus < signature > data\n");
   
    // read signature data from stdin
    size=read(0, &blob, sizeof(blob));
    if (size <= 0) die("Error reading stdin\n");
   
    err=unsign(blob,size,argv[1]);
    if (err) switch (err)
    {
        case -1: die("Failed to pack signature, too much input?\n"); break;
        case -2: die("Failed to load modulus, invalid or too long?\n"); break;
        case -3: die("Signature must be less than modulus\n"); break;
        case -4: die("Failed to unpack decrpyted signature?\n"); break;
        default: die("Unknown error %d\n", err);
    }    
    
    // write decrypted data
    write(1, blob, size);
}
#endif
#endif
