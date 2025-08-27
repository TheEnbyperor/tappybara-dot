#!/usr/bin/env bash

cd wolfssl-5.8.2

TOOLCHAIN=(~/.rustup/toolchains/esp/xtensa-esp-elf/esp-*/xtensa-esp-elf)

./configure --host=xtensa-esp32-elf \
  CC=$TOOLCHAIN/bin/xtensa-esp32-elf-gcc \
  AR=$TOOLCHAIN/bin/xtensa-esp32-elf-ar \
  --prefix=$(pwd)/../wolfssl-xtensa/ \
  CFLAGS="-DWOLFSSL_USER_SETTINGS -I$(pwd)/../ -fno-math-errno -mlongcalls -nostdlib -nodefaultlibs -nostartfiles -no-pie" \
  --disable-filesystem --disable-shared --disable-oldnames --disable-tlsv12 --enable-dtls --disable-pkcs12 \
  --enable-dtls13 --enable-dtlscid --disable-crypttests --enable-singlethreaded --enable-cryptocb --enable-debug \
  --disable-rsa --disable-examples --disable-pkcs8 --disable-sha3 --disable-threadlocal
make
make install