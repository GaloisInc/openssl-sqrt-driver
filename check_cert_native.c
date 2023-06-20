// gcc check_cert_native.c -lcrypto
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    X509 *err_cert;
    int err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    fprintf(stderr, "depth=%d ", depth);
    if (!ok)
        fprintf(stderr, "verify error:num=%d:%s\n", err,
                   X509_verify_cert_error_string(err));

    // TODO: accept self-signed certs but fail on all other errors
    if (1) {
        ok = 1;
    }

    fprintf(stderr, "verify return:%d\n", ok);
    return(ok);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <cert.pem>\n", argc >= 1 ? argv[0] : "./a.out");
        return 1;
    }

    int ret;

    // Load certificate from a buffer:
    //const unsigned char* buf_ptr = &buf;
    //X509* cert = d2i_X509(NULL, &buf_ptr, buf_len);

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "fopen failed\n");
        return 1;
    }
    X509* cert = PEM_read_X509(f, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "PEM_read_X509\n");
        return 1;
    }

    X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
    if (!param) {
        fprintf(stderr, "X509_VERIFY_PARAM_new failed\n");
        return 1;
    }
    // Skip expiration time check to avoid accessing time zone info
    ret = X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
    if (!ret) {
        fprintf(stderr, "X509_VERIFY_PARAM_set_flags failed\n");
        return 1;
    }

    X509_STORE* store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "X509_STORE_new failed\n");
        return 1;
    }
    ret = X509_STORE_set1_param(store, param);
    if (!ret) {
        fprintf(stderr, "X509_STORE_set1_param failed\n");
        return 1;
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "X509_STORE_CTX_new failed\n");
        return 1;
    }
    ret = X509_STORE_CTX_init(ctx, store, cert, NULL);
    if (!ret) {
        fprintf(stderr, "X509_STORE_CTX_init failed\n");
        return 1;
    }

    X509_STORE_CTX_set_verify_cb(ctx, verify_callback);

    ret = X509_verify_cert(ctx);
    if (!ret) {
        fprintf(stderr, "X509_verify_cert failed\n");
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "error code = %d\n", err);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        fprintf(stderr, "error depth = %d\n", depth);
        const char* err_str = X509_verify_cert_error_string(err);
        fprintf(stderr, "error = %s\n", err_str);
        return 1;
    }
    printf("verify succeeded for %s\n", argv[1]);

    return ret;

}
