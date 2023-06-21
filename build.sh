#!/bin/bash
set -e

DRIVER_DIR="$(dirname "$0")"
OPENSSL_DIR="$DRIVER_DIR/../openssl-sqrt"
#PICOLIBC_HOME="$DRIVER_DIR/../picolibc/build/image/picolibc/x86_64-unknown-fromager"
PICOLIBC_HOME="$DRIVER_DIR/../picolibc/build/image/picolibc/riscv64-unknown-fromager"
CLANG_DIR="$(clang${LLVM_SUFFIX} -print-resource-dir)"

CFLAGS="
    -target riscv64-unknown-elf -march=rv64im -fPIC
    -flto -mprefer-vector-width=1
    -nostdinc
    -isystem $CLANG_DIR/include
    -isystem $PICOLIBC_HOME/include
    -I $OPENSSL_DIR/include
    -ggdb
    -fPIC
    "

# Note: if your LLVM binaries have a version suffix (such as `llvm-link-9`),
# set the `LLVM_SUFFIX` environment variable (e.g. `LLVM_SUFFIX=-9`).


mkdir -p build/fromager

# Build the driver program.
clang${LLVM_SUFFIX} -c driver.c -o build/fromager/driver.o \
    $CFLAGS -I . $DRIVER_CFLAGS
clang${LLVM_SUFFIX} -c driver_secret.c -o build/fromager/driver_secret.bc \
    $CFLAGS -I . $DRIVER_CFLAGS

cc_objects="
        build/fromager/driver.o
        ../openssl-sqrt/libcrypto.a
    " \
    cc_secret_objects=build/fromager/driver_secret.bc \
    cc_microram_output="build/driver.ll" \
    $PICOLIBC_HOME/lib/fromager-link.sh microram
llc${LLVM_SUFFIX} "build/driver.ll" -o "build/driver.s" -relocation-model=static -mattr=+m
