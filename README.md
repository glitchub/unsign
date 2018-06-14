Standalone openssl RSA signature decryption.

unsign.c is intended to be linked into another program. However use of the
existing Makefile will compile with -DPOC to build a stand alone executable
which can accept the encrypted signature on stdin and the key modulus as hex
string on the command line.

The POC binary can be tested as follows:

Generate an openssl keypair with any number of bits from 512 to 4096 (in this
case, 1024):

  openssl req -x509 -newkey rsa:1024 -nodes -batch -keyout private.key > public.cert

Create a dummy object to sign, aka "encrypt with the private key". Length must
be the same as the number of key bits, but note the very first bit should be 0
to ensure it will always be numerically less than the modulus. In this case,
we'll create a 128 byte ASCII string:

  printf X%.0s {1..128} > XXX.txt

Now sign the string, to create a 128-byte encrypted object:

  openssl rsa -sign -raw -inkey private.key < XXX.txt > XXX.sig

Also extract the public modulus as a hex string:

  openssl x509 -modulus -noout < public.cert > modulus.txt

The encrypted signature can now be "unsigned":

  unsign $(cat modulus.txt) < XXX.sig

should produce 'XXXX...' exactly matching XXX.txt.  

In practice, unsign.c is linked into firmware without -DPOC, along with modulus
of a known signing key or keys. The private key is used by manufuacturer to
encrypt a SHA256 and assorted metadata that describes the kernel or other file
image that firmware must authenticate prior to loading. 

The firmware loads the signature data into memory and calls the unsign function
to decrypt it in place. 

