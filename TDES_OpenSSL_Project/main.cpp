#include <iostream>
#include <cstdio>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/err.h>

extern "C"{
    #include "openssl/applink.c"
};

static const unsigned char tdes_112_key[30] = {
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00, 0x12, 0x00, 0x04, 0x10,
        0x95, 0x3A, 0x41, 0x2E, 0x50, 0x47, 0x98, 0xCF, 0x74, 0x32, 0x14, 0x73, 0x40, 0xD0, 0x3A, 0xFE
};

static const unsigned char tdesKey[] = {
    0x95, 0x3A, 0x41, 0x2E, 0x50, 0x47, 0x98, 0xCF, 0x74, 0x32, 0x14, 0x73, 0x40, 0xD0, 0x3A, 0xFE
}; // 24字节的密钥

static void handleErrors();

int main() {
    const unsigned char plaintext[] = "KFCFKXQ4VW50YZYW"; // 要加密的数据
    int len;

    // 初始化OpenSSL库
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
//    system("chcp 65001");

    // 创建EVP_CIPHER_CTX结构体
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    // ================ 加密数据 ================
    unsigned char ciphertext[128] = {};
    int ciphertextLen = 0;

    // 初始化加密上下文
    if (EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), nullptr, tdesKey, nullptr) != 1) handleErrors();

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 8) != 1) handleErrors();
    ciphertextLen += len;

    // 完成加密过程
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLen, &len) != 1) handleErrors();
    ciphertextLen += len;

    // 输出密文
    std::cout << "密文: ";
    for (int i = 0; i < ciphertextLen; i++) {
        std::cout << std::hex << static_cast<int>(ciphertext[i]) << " ";
    }
    std::cout << std::dec << std::endl;

    // ================ 解密数据 ================
    unsigned char decryptedText[128] = {}; // 假设你的明文不会超过4096字节
    int decryptedTextLen = 0;

    // 初始化解密上下文
    if (EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), nullptr, tdesKey, nullptr) != 1) handleErrors();

    if (EVP_DecryptUpdate(ctx, decryptedText, &len, ciphertext, ciphertextLen) != 1) handleErrors();
    decryptedTextLen += len;

    // 完成解密过程
    if (EVP_DecryptFinal_ex(ctx, decryptedText + decryptedTextLen, &len) != 1) handleErrors();
    decryptedTextLen += len;

    // 输出解密后的明文
    std::cout << "解密后的明文: " << decryptedText << std::endl;

    // 清理资源
    EVP_CIPHER_CTX_free(ctx);

    // 清理OpenSSL库
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

static void handleErrors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}
