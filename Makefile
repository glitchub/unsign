# unsign.c is intended to be included into other code as an library.  This
# Makefile builds with -POC to builod a proof-of-concept binary, by default
# creates the RSA unsigner tool.  Use 'make TEST=(EXPMOD|MULMOD|ADD|SUB)' to
# build a program that will perform specified operation on hexadecimal string
# arguments instead. Note the POC code can be removed in production.
CFLAGS=-Wall -g -DPOC $(if $(TEST),-D$(TEST))
.PHONY: default clean
default: unsign
clean:; rm -rf unsign unsign.dSYM
