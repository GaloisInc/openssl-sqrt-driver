#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

#ifndef FROMAGER_NATIVE
# include <fromager.h>
#else
# include <stdio.h>
# include <stdint.h>
static void __cc_trace_exec(const char* s,
        uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
    fprintf(stderr, "[FUNC] %s(%lx, %lx, %lx, %lx)\n", s, arg0, arg1, arg2, arg3);
}
static void __cc_trace(const char* s) {
    fprintf(stderr, "TRACESTR %s\n", s);
}
#endif

extern const uint8_t secret_certificate[512];
extern const size_t secret_certificate_len;

int main() {
    int ret;

    // Load certificate from a buffer:
    const unsigned char* buf_ptr = secret_certificate;
    X509* cert = d2i_X509(NULL, &buf_ptr, secret_certificate_len);

    X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
    if (!param) {
        return 1;
    }
    // Skip expiration time check to avoid unsupported syscalls
    ret = X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
    if (!ret) {
        return 1;
    }

    X509_STORE* store = X509_STORE_new();
    if (!store) {
        return 1;
    }
    ret = X509_STORE_set1_param(store, param);
    if (!ret) {
        return 1;
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        return 1;
    }
    ret = X509_STORE_CTX_init(ctx, store, cert, NULL);
    if (!ret) {
        return 1;
    }

    ret = X509_verify_cert(ctx);
    if (!ret) {
        return 1;
    }

    return 0;
}
