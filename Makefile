CFLAGS = -Wall -Werror

.PHONY: test clean

unsign: main.c unsign.c

test: unsign
        # generate a private key
	openssl genrsa 1024 > private.key
        # extract the public key
	openssl rsa -modulus -noout < private.key | awk -F= '{print $$2}' > public.key
        # create a random blob numerically less than public key
	tr -dc ' -~' < /dev/urandom | head -c128 > sig.dat
        # sign the blob, ie encrypt with private key
	openssl rsautl -sign -raw -inkey private.key < sig.dat > sig.sig
        # unsign the encrypted blob to recovert the original sig.dat
	./unsign $$(cat public.key) < sig.sig > sig.unsig
        # check
	diff sig.dat sig.unsig
        # woot
	echo "Test pass!"

clean:; git clean -f
