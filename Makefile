# unsign.c is intended to be included into other code as an library.
# This Makefile builds with -POC to builod a proof-of-concept binary.
# make EXPMOD=1 to build a program that will perform expmod on arbitrary hexadeciaml strings. 
CFLAGS=-Wall -g -DPOC $(if $(EXPMOD),-DEXPMOD)
.PHONY: default clean
default: unsign
clean:; rm -rf unsign unsign.dSYM
