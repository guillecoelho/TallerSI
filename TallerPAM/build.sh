#!/bin/bash
# Build test app
g++ -Wall -o test-pam-tsi test-pam-tsi.c -lpam -lpam_misc -lgcrypt

# Build module
g++ -fPIC -Wall -c pam_tallersipwd.c -lgcrypt
ld -x --shared -o pam_tallersipwd.so pam_tallersipwd.o -lgcrypt

# Add Man manual
cp pam_tallersipw.1 /usr/share/man/man1/
