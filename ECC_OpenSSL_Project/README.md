## EC密钥生成

```
================================================================

// 生成ec私钥 pem格式
openssl ecparam -name secp256k1 -genkey -noout -out ec_private_key.pem
openssl ecparam -name secp256r1 -genkey -noout -out ec_private_key.pem

// 将pem格式私钥转为der格式
openssl ec -in ec_private_key.pem -outform DER -out ec_private_key.der

// 将der格式私钥转为pem格式
openssl ec -inform DER -in ec_private_key.der -outform PEM -out ec_private_key.pem

================================================================

// 通过pem格式私钥生成pem格式公钥
openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem

// 将pem格式公钥转为der格式
openssl ec -in ec_public_key.pem -pubin -outform DER -out ec_public_key.der

// 将der格式公钥转为pem格式
openssl ec -inform DER -pubin -in ec_public_key.der -outform PEM -out ec_public_key.pem

================================================================
```

## DER编码

```
EC公钥的DER编码示例（伪代码）：

SEQUENCE (整个数据结构是一个序列)
    INTEGER (标识椭圆曲线类型)
        OID (椭圆曲线的唯一标识符)
    BIT STRING (存储公钥的坐标点)
        OCTET STRING (X坐标)
        OCTET STRING (Y坐标)
```
```
EC私钥的简化DER编码示例（伪代码）：

SEQUENCE (整个数据结构是一个序列)
    INTEGER (标识私钥类型)
        OID (私钥的唯一标识符)
    OCTET STRING (存储私钥的值)
        INTEGER (私钥的大整数值)
```

## Prime192v1密钥格式

```angular2html
/*******************************
 *         Prime192v1
********************************/

unsigned char pub_head[26] = {    // 0x1A
	0x30, 0x49, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 
	0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01, 0x03, 0x32, 0x00
};
+
unsigned char pub_key[49];    // 0x31
=
0x4B



unsigned char pri_head[7] = {    // 0x07
	0x30, 0x5F, 0x02, 0x01, 0x01, 0x04, 0x18
};
+
unsigned char pri_key[24];    // 0x18
+
unsigned char pri_tail[17] = {    // 0x11
	0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01, 0xA1, 0x34, 0x03, 0x32, 
	0x00
};
+
unsigned char pub_key[49];    // 0x31
=
0x61
```

## TEST

```angular2html
#define IS_CREATE_KEY false
#define SECP521R1_PRI_KEY_SIZE 0xDF
#define SECP521R1_PUB_KEY_SIZE 0x9E // 0x85

if (IS_CREATE_KEY) {
        EVP_PKEY *key = nullptr;
        // new_ec_key();
        FILE *fp = nullptr;
        BIO *bio_out = nullptr;
        unsigned char pri_key_der[SECP521R1_PRI_KEY_SIZE];
        unsigned char pub_key_der[SECP521R1_PUB_KEY_SIZE] = {
                0x30, 0x81, 0x9B, 0x30, 0x10, 0x06, 0x07, 0x2A,
                0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05,
                0x2B, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00
        };
        unsigned char *pri_key_der_ptr = pri_key_der;
        unsigned char *pub_key_der_ptr = pub_key_der + sizeof(char) * 25;

        // 生成521位公私钥
        key = EVP_EC_gen("secp521r1");
        if (key == nullptr) {
            BIO_printf(bio_out, "Error generating the ECC key.");
            abort();
        }

        // 将公私钥转为der格式存于buf内
        i2d_PrivateKey(key, &pri_key_der_ptr);
        i2d_PublicKey(key, &pub_key_der_ptr);

        std::cout << "Pri:" << std::endl;
        for (size_t i = 0; i < sizeof(char) * 25 / sizeof(char); ++i) {
            std::cout << "0x" << std::hex << static_cast<int>(pri_key_der[0]) << " ";
        }
        std::cout << std::endl;

        std::cout << "Pub:" << std::endl;
        for (size_t i = 0; i < sizeof(char) * 25 / sizeof(char); ++i) {
            std::cout << "0x" << std::hex << static_cast<int>(pri_key_der[0]) << " ";
        }
        std::cout << std::endl;

        // ec_encode
        OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                                                                    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, "PEM",
                                                               "type-specific", nullptr);
        fp = fopen("pri.der", "w");
        OSSL_ENCODER_CTX_set_passphrase(ectx, pri_key_der, SECP521R1_PRI_KEY_SIZE);
        OSSL_ENCODER_to_fp(ectx, fp);
        fclose(fp);
        OSSL_ENCODER_CTX_free(ectx);

        ectx = nullptr;
        ectx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                                                  | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, "PEM",
                                             "SubjectPublicKeyInfo",
                                             nullptr);
        fp = fopen("pub.der", "w");
        ret = OSSL_ENCODER_CTX_set_passphrase(ectx, pub_key_der, 0x9E);
        ret = OSSL_ENCODER_to_fp(ectx, fp);
        fclose(fp);
        OSSL_ENCODER_CTX_free(ectx);

        // ======== 将公私钥以文件形式输出 ========
//        fp = fopen("pri.key", "w");
//        bio_out = BIO_new_fp(fp, BIO_NOCLOSE);
//        BIO_set_flags(bio_out, BIO_FLAGS_WRITE);
//        ret = EVP_PKEY_print_private(bio_out, key, 0, nullptr);

        if (bio_out != nullptr) { BIO_free(bio_out); }
        if (ectx != nullptr) { OSSL_ENCODER_CTX_free(ectx); }
        EVP_PKEY_free(key);
    }
```