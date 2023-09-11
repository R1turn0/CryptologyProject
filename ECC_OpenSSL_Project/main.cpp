#include <iostream>
#include <cstring>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/aes.h>

extern "C" {
#include "openssl/applink.c"
};

/*
 * IS_CREATE_EC_KEY         创建密钥开关
 * IS_LOAD_EC_KEY           输入密钥开关
  *IS_ENCRYPTION_PRI_KEY    加密pem私钥开关
 * IS_ENCODE_EC_KEY         解码密钥开关
 * IS_SIGN_VERIFY_DATE      签名/验签开关
 * EC_KEY_TYPE              EC密钥格式 "FILE"/“BUFFER”/"STDIN"
 */
#define IS_CREATE_EC_KEY        false
#define IS_LOAD_EC_KEY          !(IS_CREATE_EC_KEY)
#define IS_ENCRYPTION_PRI_KEY   false
#define IS_ENCODE_EC_KEY        true
#define IS_SIGN_VERIFY_DATE     true
#define EC_KEY_TYPE             "BUFFER"

// AES-256-CBC密钥
static const char *KEY_AES_256_CBC = "BeyuATQRSNXI2FI3NDj6I/hkguMxm5yN";

static const char *hamlet_1 =
        "To be, or not to be, that is the question,\n"
        "Whether tis nobler in the minde to suffer\n"
        "The slings and arrowes of outragious fortune,\n"
        "Or to take Armes again in a sea of troubles,\n";
static const char *hamlet_2 =
        "And by opposing, end them, to die to sleep;\n"
        "No more, and by a sleep, to say we end\n"
        "The heart-ache, and the thousand natural shocks\n"
        "That flesh is heir to? tis a consumation\n";

static const unsigned char pri_key_der[] = {
        0x30, 0x5F, 0x02, 0x01, 0x01, 0x04, 0x18, 0x92, 0x6A, 0x4A, 0x94, 0x6B, 0x59, 0xF6, 0x9E, 0xD2,
        0x3A, 0x58, 0x97, 0xAA, 0xF5, 0x00, 0x87, 0x97, 0xDD, 0xAB, 0x06, 0x3B, 0xFF, 0x3D, 0x51, 0xA0,
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01, 0xA1, 0x34, 0x03, 0x32, 0x00,
        0x04, 0x5A, 0x7C, 0x20, 0xE8, 0xB5, 0xB9, 0x5B, 0x06, 0x03, 0xA4, 0x7B, 0xAC, 0x48, 0x18, 0x92,
        0xA3, 0x71, 0x77, 0x7A, 0xA4, 0x6A, 0xCA, 0x22, 0x27, 0x2C, 0x35, 0x67, 0x91, 0x59, 0x52, 0x18,
        0x0C, 0xB7, 0x9F, 0xD6, 0x77, 0x1C, 0x48, 0x3A, 0x48, 0x3F, 0x84, 0x0D, 0x42, 0xA1, 0x0F, 0xD0,
        0x2B
};

static const unsigned char pub_key_der[] = {
        0x30, 0x49, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01, 0x03, 0x32, 0x00, 0x04, 0x5A, 0x7C, 0x20, 0xE8, 0xB5,
        0xB9, 0x5B, 0x06, 0x03, 0xA4, 0x7B, 0xAC, 0x48, 0x18, 0x92, 0xA3, 0x71, 0x77, 0x7A, 0xA4, 0x6A,
        0xCA, 0x22, 0x27, 0x2C, 0x35, 0x67, 0x91, 0x59, 0x52, 0x18, 0x0C, 0xB7, 0x9F, 0xD6, 0x77, 0x1C,
        0x48, 0x3A, 0x48, 0x3F, 0x84, 0x0D, 0x42, 0xA1, 0x0F, 0xD0, 0x2B
};

static const unsigned char pri_key_pem[] = {
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MF8CAQEEGJJqSpRrWfae0jpYl6r1AIeX3asGO/89UaAKBggqhkjOPQMBAaE0AzIA\n"
        "BFp8IOi1uVsGA6R7rEgYkqNxd3qkasoiJyw1Z5FZUhgMt5/WdxxIOkg/hA1CoQ/Q\n"
        "Kw==\n"
        "-----END EC PRIVATE KEY-----"
};

static const unsigned char pub_key_pem[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEWnwg6LW5WwYDpHusSBiSo3F3eqRq\n"
        "yiInLDVnkVlSGAy3n9Z3HEg6SD+EDUKhD9Ar\n"
        "-----END PUBLIC KEY-----"
};

static const char *propq = nullptr;

static int get_key_values(EVP_PKEY *pkey);

static EVP_PKEY *do_ec_keygen(void);

static EVP_PKEY *load_key(OSSL_LIB_CTX *libctx, void *f, const char *passphrase);

static int store_key(EVP_PKEY *pkey, FILE *f, const char *passphrase);

static EVP_PKEY *get_key(OSSL_LIB_CTX *libctx, const char *propq, int pub);

static int demo_sign(OSSL_LIB_CTX *libctx, const char *sig_name,
                     size_t *sig_out_len, unsigned char **sig_out_value);

static int demo_verify(OSSL_LIB_CTX *libctx, const char *sig_name,
                       size_t sig_len, unsigned char *sig_value);

int main() {
    int ret = EXIT_FAILURE;
    EVP_PKEY *pkey = nullptr;
    OSSL_LIB_CTX *libctx = nullptr;
    const char *passphrase_in = KEY_AES_256_CBC;
    const char *passphrase_out = KEY_AES_256_CBC;

    const char *sig_name = "SHA3-512";
    size_t sig_len = 0;
    unsigned char *sig_value = nullptr;

    // ================ 创建密钥 ================
    if (IS_CREATE_EC_KEY) {
        pkey = do_ec_keygen();
        if (pkey == nullptr)
            goto cleanup;
        if (!get_key_values(pkey))
            goto cleanup;
        std::cout << std::endl;
    }

    // ================ 加载密钥 ================
    if (IS_LOAD_EC_KEY) {
        // 私钥\n公钥 or input(公钥)+input(私钥)
//        pkey = load_key(libctx, stdin, passphrase_in);
        pkey = load_key(libctx, (void*)pri_key_pem, passphrase_in);
        if (pkey == nullptr) {
            fprintf(stderr, "Failed to decode key\n");
            goto cleanup;
        }
        std::cout << std::endl;
    }

    /*
     * At this point we can write out the generated key using
     * i2d_PrivateKey() and i2d_PublicKey() if required.
     */

    // ================ 密钥解码转储为pem格式 ================
    if (IS_ENCODE_EC_KEY) {
        FILE *fp = nullptr;
        fp = fopen("ec_public_key.pem", "w");
        if (store_key(pkey, /*stdout*/fp, nullptr) == 0) {
            fprintf(stderr, "Failed to encode key\n");
            goto cleanup;
        }
        fclose(fp);
        fp = fopen("ec_private_key.pem", "w");
        std::cout << std::endl;
        if (store_key(pkey, /*stdout*/fp, passphrase_out) == 0) {
            fprintf(stderr, "Failed to encode key\n");
            goto cleanup;
        }
        fclose(fp);
        fp = nullptr;
        std::cout << std::endl;
    }

    // ================ 签名/验签 ================
    if (IS_SIGN_VERIFY_DATE) {
        libctx = OSSL_LIB_CTX_new();
        if (libctx == nullptr) {
            fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
            goto cleanup;
        }
        if (!demo_sign(libctx, sig_name, &sig_len, &sig_value)) {
            fprintf(stderr, "demo_sign failed.\n");
            goto cleanup;
        }
        if (!demo_verify(libctx, sig_name, sig_len, sig_value)) {
            fprintf(stderr, "demo_verify failed.\n");
            goto cleanup;
        }
        std::cout << std::endl;
    }

    // ================ clean ================
    ret = EXIT_SUCCESS;
    cleanup:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    if (pkey != nullptr)
        EVP_PKEY_free(pkey);
    if (libctx != nullptr)
        OSSL_LIB_CTX_free(libctx);

    return 0;
}

/*
 * The following code shows how to generate an EC key from a curve name
 * with additional parameters. If only the curve name is required then the
 * simple helper can be used instead i.e. Either
 * pkey = EVP_EC_gen(curvename); OR
 * pkey = EVP_PKEY_Q_keygen(libctx, propq, "EC", curvename);
 */
static EVP_PKEY *do_ec_keygen(void) {
    /*
     * The libctx and propq can be set if required, they are included here
     * to show how they are passed to EVP_PKEY_CTX_new_from_name().
     */
    OSSL_LIB_CTX *libctx = nullptr;
    const char *propq = nullptr;
    EVP_PKEY *key = nullptr;
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *genctx = nullptr;
    const char *curvename = "P-192";    // P-256
    int use_cofactordh = 1;

    genctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);
    if (genctx == nullptr) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init() failed\n");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *) curvename, 0);
    /*
     * This is an optional parameter.
     * For many curves where the cofactor is 1, setting this has no effect.
     */
    params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                         &use_cofactordh);
    params[2] = OSSL_PARAM_construct_end();
    if (!EVP_PKEY_CTX_set_params(genctx, params)) {
        fprintf(stderr, "EVP_PKEY_CTX_set_params() failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Generating EC key\n\n");
    if (EVP_PKEY_generate(genctx, &key) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate() failed\n");
        goto cleanup;
    }
    cleanup:
    EVP_PKEY_CTX_free(genctx);
    return key;
}

/*
 * The following code shows how retrieve key data from the generated
 * EC key. See doc/man7/EVP_PKEY-EC.pod for more information.
 *
 * EVP_PKEY_print_private() could also be used to display the values.
 */
static int get_key_values(EVP_PKEY *pkey) {
    int ret = 0;
    char out_curvename[80];
    unsigned char out_pubkey[80];
    unsigned char out_privkey[80];
    BIGNUM *out_priv = nullptr;
    size_t out_pubkey_len, out_privkey_len = 0;

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        out_curvename, sizeof(out_curvename),
                                        nullptr)) {
        fprintf(stderr, "Failed to get curve name\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         out_pubkey, sizeof(out_pubkey),
                                         &out_pubkey_len)) {
        fprintf(stderr, "Failed to get public key\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &out_priv)) {
        fprintf(stderr, "Failed to get private key\n");
        goto cleanup;
    }

    out_privkey_len = BN_bn2bin(out_priv, out_privkey);
    if (out_privkey_len <= 0 || out_privkey_len > sizeof(out_privkey)) {
        fprintf(stderr, "BN_bn2bin failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Curve name: %s\n", out_curvename);
    fprintf(stdout, "Public key:\n");
    BIO_dump_indent_fp(stdout, out_pubkey, out_pubkey_len, 2);
    fprintf(stdout, "Private Key:\n");
    BIO_dump_indent_fp(stdout, out_privkey, out_privkey_len, 2);

    ret = 1;
    cleanup:
    /* Zeroize the private key data when we free it */
    BN_clear_free(out_priv);
    return ret;
}

/*
 * Load a PEM-encoded EC key from a file, optionally decrypting it with a
 * supplied passphrase.
 */
static EVP_PKEY *load_key(OSSL_LIB_CTX *libctx, void *f, const char *passphrase) {
    int ret = 0;
    EVP_PKEY *pkey = nullptr;
    OSSL_DECODER_CTX *dctx = nullptr;
    int selection = 0;

    /*
     * Create PEM decoder context expecting an EC key.
     *
     * For raw (non-PEM-encoded) keys, change "PEM" to "DER".
     *
     * The selection argument here specifies whether we are willing to accept a
     * public key, private key, or either. If it is set to zero, either will be
     * accepted. If set to EVP_PKEY_KEYPAIR, a private key will be required, and
     * if set to EVP_PKEY_PUBLIC_KEY, a public key will be required.
     */
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", nullptr, "EC",
                                         selection,
                                         libctx, propq);
    if (dctx == nullptr) {
        fprintf(stderr, "OSSL_DECODER_CTX_new_for_pkey() failed\n");
        goto cleanup;
    }

    /*
     * Set passphrase if provided; needed to decrypt encrypted PEM files.
     * If the input is not encrypted, any passphrase provided is ignored.
     *
     * Alternative methods for specifying passphrases exist, such as a callback
     * (see OSSL_DECODER_CTX_set_passphrase_cb(3)), which may be more useful for
     * interactive applications which do not know if a passphrase should be
     * prompted for in advance, or for GUI applications.
     */
    if (passphrase != nullptr && IS_ENCRYPTION_PRI_KEY) {
        if (OSSL_DECODER_CTX_set_passphrase(dctx,
                                            (const unsigned char *) passphrase,
                                            strlen(passphrase)) == 0) {
            fprintf(stderr, "OSSL_DECODER_CTX_set_passphrase() failed\n");
            goto cleanup;
        }
    }

    if (!strcmp(EC_KEY_TYPE, "FLIE")) {
        /* Do the decode, reading from file. */
        if (OSSL_DECODER_from_fp(dctx, (FILE *) f) == 0) {
            fprintf(stderr, "OSSL_DECODER_from_fp() failed\n");
            goto cleanup;
        }
    } else if (!strcmp(EC_KEY_TYPE, "BUFFER")) {
        /* Do the decode, reading from buffer. */
        const auto *pdate = static_cast<const unsigned char *>(f);
        size_t pdata_len = strlen(reinterpret_cast<const char *>(pdate));
        if (OSSL_DECODER_from_data(dctx, &pdate, &pdata_len) == 0) {
            fprintf(stderr, "OSSL_DECODER_from_fp() failed\n");
            goto cleanup;
        }
    } else if (!strcmp(EC_KEY_TYPE, "STDIN")) {
        if (OSSL_DECODER_from_fp(dctx, stdin) == 0) {
            fprintf(stderr, "OSSL_DECODER_from_fp() failed\n");
            goto cleanup;
        }
    } else {
        fprintf(stderr, "OSSL_DECODER_from_fp() failed\n");
        goto cleanup;
    }

    ret = 1;
    cleanup:
    OSSL_DECODER_CTX_free(dctx);

    /*
     * pkey is created by OSSL_DECODER_CTX_new_for_pkey, but we
     * might fail subsequently, so ensure it's properly freed
     * in this case.
     */
    if (ret == 0) {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }

    return pkey;
}

/*
 * Store a EC public or private key to a file using PEM encoding.
 *
 * If a passphrase is supplied, the file is encrypted, otherwise
 * it is unencrypted.
 */
static int store_key(EVP_PKEY *pkey, FILE *f, const char *passphrase) {
    int ret = 0;
    int selection;
    OSSL_ENCODER_CTX *ectx = nullptr;

    /*
     * Create a PEM encoder context.
     *
     * For raw (non-PEM-encoded) output, change "PEM" to "DER".
     *
     * The selection argument controls whether the private key is exported
     * (EVP_PKEY_KEYPAIR), or only the public key (EVP_PKEY_PUBLIC_KEY). The
     * former will fail if we only have a public key.
     *
     * Note that unlike the decode API, you cannot specify zero here.
     *
     * Purely for the sake of demonstration, here we choose to export the whole
     * key if a passphrase is provided and the public key otherwise.
     */
    selection = (passphrase != nullptr)
                ? EVP_PKEY_KEYPAIR
                : EVP_PKEY_PUBLIC_KEY;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", nullptr, propq);
    if (ectx == nullptr) {
        fprintf(stderr, "OSSL_ENCODER_CTX_new_for_pkey() failed\n");
        goto cleanup;
    }

    /*
     * Set passphrase if provided; the encoded output will then be encrypted
     * using the passphrase.
     *
     * Alternative methods for specifying passphrases exist, such as a callback
     * (see OSSL_ENCODER_CTX_set_passphrase_cb(3), just as for OSSL_DECODER_CTX;
     * however you are less likely to need them as you presumably know whether
     * encryption is desired in advance.
     *
     * Note that specifying a passphrase alone is not enough to cause the
     * key to be encrypted. You must set both a cipher and a passphrase.
     */
    if (passphrase != nullptr && IS_ENCRYPTION_PRI_KEY) {
        /*
         * Set cipher. Let's use AES-256-CBC, because it is
         * more quantum resistant.
         */
        if (OSSL_ENCODER_CTX_set_cipher(ectx, "AES-256-CBC", propq) == 0) {
            fprintf(stderr, "OSSL_ENCODER_CTX_set_cipher() failed\n");
            goto cleanup;
        }

        /* Set passphrase. */
        if (OSSL_ENCODER_CTX_set_passphrase(ectx,
                                            (const unsigned char *) passphrase,
                                            strlen(passphrase)) == 0) {
            fprintf(stderr, "OSSL_ENCODER_CTX_set_passphrase() failed\n");
            goto cleanup;
        }
    }

    /* Do the encode, writing to the given file. */
    if (OSSL_ENCODER_to_fp(ectx, f) == 0) {
        fprintf(stderr, "OSSL_ENCODER_to_fp() failed\n");
        goto cleanup;
    }
    /* Do the encode, writing to the given buffer. */
    if (OSSL_ENCODER_to_fp(ectx, stdout) == 0) {
        fprintf(stderr, "OSSL_ENCODER_to_fp() failed\n");
        goto cleanup;
    }

    ret = 1;
    cleanup:
    OSSL_ENCODER_CTX_free(ectx);
    return ret;
}

/*
 * For demo_sign, load EC private key priv_key from pri_key_der[].
 * For demo_verify, load EC public key pub_key from pub_key_der[].
 */
static EVP_PKEY *get_key(OSSL_LIB_CTX *libctx, const char *propq, int pub) {
    OSSL_DECODER_CTX *dctx = nullptr;
    EVP_PKEY *pkey = nullptr;
    int selection;
    const unsigned char *data;
    size_t data_len;

    if (pub) {
        selection = EVP_PKEY_PUBLIC_KEY;
        data = pub_key_der;
        data_len = sizeof(pub_key_der);
    } else {
        selection = EVP_PKEY_KEYPAIR;
        data = pri_key_der;
        data_len = sizeof(pri_key_der);
    }
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", nullptr, "EC",
                                         selection, libctx, propq);
    (void) OSSL_DECODER_from_data(dctx, &data, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    if (pkey == nullptr)
        fprintf(stderr, "Failed to load %s key.\n", pub ? "public" : "private");
    return pkey;
}

static int demo_sign(OSSL_LIB_CTX *libctx, const char *sig_name,
                     size_t *sig_out_len, unsigned char **sig_out_value) {
    int ret = 0, pub = 0;
    size_t sig_len;
    void *sig_value = nullptr;
    const char *propq = nullptr;
    EVP_MD_CTX *sign_context = nullptr;
    EVP_PKEY *priv_key = nullptr;

    /* Get private key */
    if (!strcmp(EC_KEY_TYPE, "FILE")) {
        FILE *fp = fopen("ec_private_key.pem", "r");
        priv_key = load_key(libctx, /*stdin*/fp, nullptr);
        fclose(fp);
        fp = nullptr;
    } else if (!strcmp(EC_KEY_TYPE, "BUFFER")) {
        priv_key = load_key(libctx, (void *) pri_key_pem, nullptr);
//        priv_key = get_key(libctx, propq, pub);
    } else if (!strcmp(EC_KEY_TYPE, "STDIN")) {
        std::cout << "Please input EC private key:" << std::endl;
        priv_key = load_key(libctx, stdin, nullptr);
    }
    if (priv_key == nullptr) {
        fprintf(stderr, "Get private key failed.\n");
        goto cleanup;
    }
    /*
     * Make a message signature context to hold temporary state
     * during signature creation
     */
    sign_context = EVP_MD_CTX_new();
    if (sign_context == nullptr) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /*
     * Initialize the sign context to use the fetched
     * sign provider.
     */
    if (!EVP_DigestSignInit_ex(sign_context, nullptr, sig_name,
                               libctx, nullptr, priv_key, nullptr)) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        goto cleanup;
    }
    /*
     * EVP_DigestSignUpdate() can be called several times on the same context
     * to include additional data.
     */
    if (!EVP_DigestSignUpdate(sign_context, hamlet_1, strlen(hamlet_1))) {
        fprintf(stderr, "EVP_DigestSignUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (!EVP_DigestSignUpdate(sign_context, hamlet_2, strlen(hamlet_2))) {
        fprintf(stderr, "EVP_DigestSignUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    /* Call EVP_DigestSignFinal to get signature length sig_len */
    if (!EVP_DigestSignFinal(sign_context, nullptr, &sig_len)) {
        fprintf(stderr, "EVP_DigestSignFinal failed.\n");
        goto cleanup;
    }
    if (sig_len <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal returned invalid signature length.\n");
        goto cleanup;
    }
    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == nullptr) {
        fprintf(stderr, "No memory.\n");
        goto cleanup;
    }
    if (!EVP_DigestSignFinal(sign_context, (unsigned char *) sig_value, &sig_len)) {
        fprintf(stderr, "EVP_DigestSignFinal failed.\n");
        goto cleanup;
    }
    *sig_out_len = sig_len;
    *sig_out_value = (unsigned char *) sig_value;
    fprintf(stdout, "Generating signature:\n");
    BIO_dump_indent_fp(stdout, sig_value, sig_len, 2);
    fprintf(stdout, "\n");
    ret = 1;

    cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    if (!ret)
        OPENSSL_free(sig_value);
    EVP_PKEY_free(priv_key);
    EVP_MD_CTX_free(sign_context);
    return ret;
}

static int demo_verify(OSSL_LIB_CTX *libctx, const char *sig_name,
                       size_t sig_len, unsigned char *sig_value) {
    int ret = 0, pub = 1;
    const char *propq = nullptr;
    EVP_MD_CTX *verify_context = nullptr;
    EVP_PKEY *pub_key = nullptr;

    /*
     * Make a verify signature context to hold temporary state
     * during signature verification
     */
    verify_context = EVP_MD_CTX_new();
    if (verify_context == nullptr) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /* Get public key */
    if (!strcmp(EC_KEY_TYPE, "FILE")) {
        FILE *fp = fopen("ec_public_key.pem", "r");
        pub_key = load_key(libctx, /*stdin*/fp, nullptr);
        fclose(fp);
        fp = nullptr;
    } else if (!strcmp(EC_KEY_TYPE, "BUFFER")) {
        pub_key = load_key(libctx, (void *) pub_key_pem, nullptr);
//        pub_key = get_key(libctx, propq, pub);
    } else if (!strcmp(EC_KEY_TYPE, "STDIN")) {
        std::cout << "Please input EC public key:" << std::endl;
        pub_key = load_key(libctx, stdin, nullptr);
    }
    if (pub_key == nullptr) {
        fprintf(stderr, "Get public key failed.\n");
        goto cleanup;
    }
    /* Verify */
    if (!EVP_DigestVerifyInit_ex(verify_context, nullptr, sig_name,
                                 libctx, nullptr, pub_key, nullptr)) {
        fprintf(stderr, "EVP_DigestVerifyInit failed.\n");
        goto cleanup;
    }
    /*
     * EVP_DigestVerifyUpdate() can be called several times on the same context
     * to include additional data.
     */
    if (!EVP_DigestVerifyUpdate(verify_context, hamlet_1, strlen(hamlet_1))) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (!EVP_DigestVerifyUpdate(verify_context, hamlet_2, strlen(hamlet_2))) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestVerifyFinal(verify_context, sig_value, sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyFinal failed.\n");
        goto cleanup;
    }
    fprintf(stdout, "Signature verified.\n");
    ret = 1;

    cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    EVP_PKEY_free(pub_key);
    EVP_MD_CTX_free(verify_context);
    return ret;
}
