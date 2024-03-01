#!/bin/bash
set -e

DRIVER_DIR="$(dirname "$0")"
OPENSSL_DIR="$DRIVER_DIR/../openssl-sqrt"
case "${CC_TARGET:=riscv64}" in
    riscv64)
        PICOLIBC_HOME="$DRIVER_DIR/../picolibc/build/image/picolibc/riscv64-unknown-fromager"
        target_cflags="-target riscv64-unknown-elf -march=rv64im"
        link_mode=microram
        openssl_build_dir=../openssl-sqrt/build
        ;;
    x86_64)
        PICOLIBC_HOME="$DRIVER_DIR/../picolibc/build-x86/image/picolibc/x86_64-unknown-fromager"
        target_cflags=""
        link_mode=native
        openssl_build_dir=../openssl-sqrt/build-x86
        ;;
    *)
        echo "unknown target $target" 1>&2
        exit 1
        ;;
esac
CLANG_DIR="$(clang${LLVM_SUFFIX} -print-resource-dir)"

CFLAGS="
    $target_cflags
    -flto -mprefer-vector-width=1
    -nostdinc
    -isystem $CLANG_DIR/include
    -isystem $PICOLIBC_HOME/include
    -I $OPENSSL_DIR/include
    -I $openssl_build_dir/include
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
        $openssl_build_dir/libcrypto.a
    " \
    cc_secret_objects=build/fromager/driver_secret.bc \
    cc_microram_output="build/driver.ll" \
    bash -x $PICOLIBC_HOME/lib/fromager-link.sh $link_mode

if [ "$CC_TARGET" = "riscv64" ]; then
    # FIXME (HACK): remove thread-local flag from errno and _localtime_buf
    # We should instead patch picolibc to not make errno thread-local
    sed -i -e 's/thread_local(localexec)//' build/driver.ll
    llc${LLVM_SUFFIX} "build/driver.ll" -o "build/driver.s" -relocation-model=static -mattr=+m
fi
