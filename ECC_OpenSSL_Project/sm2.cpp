#include "openssl/types.h"
#include "openssl/x509.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <iostream>
#include <memory>
#include "inc.h"

class sm2PrivateKey;

struct EVP_CUNSTOM {
    EVP_PKEY *pkey = nullptr;

    ~EVP_CUNSTOM() {
        if (pkey != nullptr) {
            EVP_PKEY_free(pkey);
        }
    }
};

class sm2PublicKey {
public:
    sm2PublicKey() = default;

    sm2PublicKey(const sm2PublicKey &other) {
        m_pkey = other.m_pkey;
    }

//    sm2PublicKey(const std::string &pub_str);

    sm2PublicKey(const unsigned char *pub_str, size_t len);

    std::string Encrypt(const std::string &message, std::string &error);

    bool SignatureVerification(const std::string &signature, const std::string &message, std::string &error);


//    std::string GetPublicString();

//    std::string GetPublicStringBase64();

private:
    std::shared_ptr<EVP_CUNSTOM> m_pkey = nullptr;//使用shared_ptr 防止拷贝构造的时候造成内存泄漏和意外释放
};

class sm2PrivateKey {
public:
    sm2PrivateKey();

//    sm2PrivateKey(const std::string &priv_str);

    sm2PublicKey CreatePublic();

    std::string Decrypt(const std::string &encoded, std::string &error);

    std::string Signature(const std::string &message, std::string &error);

//    std::string GetPrivateString();

private:
    std::shared_ptr<EVP_CUNSTOM> M_PKEY = nullptr;
};

// 生成密钥对
sm2PrivateKey::sm2PrivateKey() {
    EVP_PKEY *ret = nullptr;

    EVP_PKEY_CTX *pkctx = nullptr;

    pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, nullptr);//创建sm2 上下文
    if (pkctx == nullptr) {
        errorL("EVP_PKEY_CTX_new_id");
        return;
    }
    int retV = 1;
    retV = EVP_PKEY_keygen_init(pkctx);//初始化sm2 上下文

    if (retV <= 0) {
        errorL("EVP_PKEY_keygen_init:" << GetErrorStr());
        EVP_PKEY_CTX_free(pkctx);
        return;
    }

    retV = EVP_PKEY_keygen(pkctx, &ret);//生成密钥对
    if (retV <= 0) {
        errorL("EVP_PKEY_keygen:" << GetErrorStr());
        EVP_PKEY_CTX_free(pkctx);
        return;
    }
    auto *cst = new EVP_CUNSTOM{ret};
    M_PKEY = std::shared_ptr<EVP_CUNSTOM>(cst);
    EVP_PKEY_CTX_free(pkctx);
}

// 导出公钥和导入公钥
sm2PublicKey sm2PrivateKey::CreatePublic() {
    unsigned char *buffer = nullptr;
    int retV = i2d_PUBKEY(M_PKEY->pkey, &buffer);//导出
    if (retV <= 0) {
        errorL("i2d_PUBKEY:" << GetErrorStr());
        return sm2PublicKey{};
    }
    //buffer 里的是公钥二进制
    sm2PublicKey pub(buffer, retV);
    //OPENSSL_free(buffer);
    return pub;
}

sm2PublicKey::sm2PublicKey(const unsigned char *pub_str, size_t len) {
    EVP_PKEY *pkey_t = nullptr;
    //pkey_t=d2i_PublicKey(EVP_PKEY_SM2,NULL, &pub_str, len);
    pkey_t = d2i_PUBKEY(nullptr, &pub_str, len);//导入
    std::string error;
    if (pkey_t == nullptr) {
        error = GetErrorStr();
        errorL(error);
        return;
    }
    auto *cst = new EVP_CUNSTOM{pkey_t};
    m_pkey = std::shared_ptr<EVP_CUNSTOM>(cst);
}

// 公钥加密
std::string sm2PublicKey::Encrypt(const std::string &message, std::string &error) {
    std::string encodedstr;
    EVP_PKEY_CTX *pkctx = nullptr;
    int retV = 1;
    if (!(pkctx = EVP_PKEY_CTX_new(m_pkey->pkey, nullptr))) {//生成上下文
        error = GetErrorStr();
        errorL("EVP_PKEY_CTX_new:" << error);
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }
    retV = EVP_PKEY_encrypt_init(pkctx);//加密初始化
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_PKEY_encrypt_init:" << error);
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }

    size_t outbuflen = 0;
    unsigned char *outbuf = nullptr;
    retV = EVP_PKEY_encrypt(pkctx, nullptr, &outbuflen,
                            (const unsigned char *) message.c_str(), message.size());//加密 （传NULL 仅获取密文长度）
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_PKEY_encrypt:" << error);
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }
    if (outbuflen == 0) {
        errorL("EVP_PKEY_encrypt:" << "no memery");
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }

    outbuf = new unsigned char[outbuflen];

    retV = EVP_PKEY_encrypt(pkctx, outbuf, &outbuflen,
                            (const unsigned char *) message.c_str(), message.size());//加密
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_PKEY_encrypt:" << error);
        EVP_PKEY_CTX_free(pkctx);
        delete[] outbuf;
        return "";
    }
    encodedstr = std::string((const char *) outbuf, outbuflen);//获取结果
    delete[] outbuf;
    EVP_PKEY_CTX_free(pkctx);
    return encodedstr;
}

// 私钥解密
std::string sm2PrivateKey::Decrypt(const std::string &encoded,
                                   std::string &error) {
    std::string decodedstr;
    EVP_PKEY_CTX *pkctx = nullptr;
    unsigned char *outbuf = nullptr;
    size_t outlen = 0;

    int retV = 1;
    if (!(pkctx = EVP_PKEY_CTX_new(M_PKEY->pkey, nullptr))) {//创建EVP 上下文
        error = GetErrorStr();
        errorL("EVP_PKEY_CTX_new:" << error);
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }
    retV = EVP_PKEY_decrypt_init(pkctx);// 解密初始化
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_PKEY_decrypt_init:" << error);
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }
    retV = EVP_PKEY_decrypt(pkctx, nullptr, &outlen,
                            (const unsigned char *) encoded.c_str(), encoded.size());//解密
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_PKEY_encrypt_init:" << error);
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }

    if (outlen == 0) {
        errorL("EVP_PKEY_decrypt:" << error);
        EVP_PKEY_CTX_free(pkctx);
        return "";
    }

    outbuf = new unsigned char[outlen];

    retV = EVP_PKEY_decrypt(pkctx, outbuf, &outlen,
                            (const unsigned char *) encoded.c_str(), encoded.size());//解密
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_PKEY_encrypt_init:" << error);
        EVP_PKEY_CTX_free(pkctx);
        delete[] outbuf;
        return "";
    }

    decodedstr = std::string((const char *) outbuf, outlen);
    delete[] outbuf;

    EVP_PKEY_CTX_free(pkctx);
    return decodedstr;
}

// 私钥签名
std::string sm2PrivateKey::Signature(const std::string &message, std::string &error) {
    std::string signatured;
    EVP_MD_CTX *mdctx = nullptr;
    unsigned char *outbuf = nullptr;
    size_t outbuflen = 0;
    int retV = 0;
    if (!(mdctx = EVP_MD_CTX_create())) {//创建摘要上下文
        error = GetErrorStr();
        errorL("EVP_MD_CTX_create:" << error);
        return "";
    }
    retV = EVP_DigestSignInit(mdctx, nullptr, EVP_sm3(),//使用sm3 摘要算法
                              nullptr, M_PKEY->pkey);//签名初始化
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_DigestSignInit:" << error);
        EVP_MD_CTX_free(mdctx);
        return "";
    }


    retV = EVP_DigestSignUpdate(mdctx, message.c_str(), message.size());//更新签名内容
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_DigestSignUpdate:" << error);
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    retV = EVP_DigestSignFinal(mdctx, nullptr, &outbuflen);//获取签名长度
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_DigestSignFinal:" << error);
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    outbuf = new unsigned char[outbuflen];

    retV = EVP_DigestSignFinal(mdctx, outbuf, &outbuflen);//获取签名结果
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_DigestSignFinal:" << error);
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    signatured = std::string((const char *) outbuf, outbuflen);
    delete[] outbuf;
    return signatured;
}

// 公钥验签
bool sm2PublicKey::SignatureVerification(const std::string &signature, const std::string &message, std::string &error) {
    std::string signatured;
    EVP_MD_CTX *mdctx = nullptr;
    int retV = 0;
    if (!(mdctx = EVP_MD_CTX_create())) {//创建摘要上下文
        error = GetErrorStr();
        errorL("EVP_MD_CTX_create:" << error);
        return false;
    }
    retV = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sm3(), nullptr, m_pkey->pkey);//验签初始化
    if (retV <= 0) {
        error = GetErrorStr();
        errorL("EVP_DigestVerifyInit:" << error)
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    retV = EVP_DigestVerifyUpdate(mdctx, message.c_str(), message.size());//更新验签内容
    if (retV <= 0) {
        error = GetErrorStr();
        EVP_MD_CTX_free(mdctx);
        errorL("EVP_DigestVerifyUpdate:" << error);
        return false;
    }
    retV = EVP_DigestVerifyFinal(mdctx, (const unsigned char *) signature.c_str(), signature.size());//验证签名
    if (retV <= 0) {
        error = GetErrorStr();
        EVP_MD_CTX_free(mdctx);
        errorL("EVP_DigestVerifyFinal:" << error);
        return false;
    }
    EVP_MD_CTX_free(mdctx);
    return true;
}


#ifndef ECC_PROJECT_INC_H
#define ECC_PROJECT_INC_H

#include <iostream>

#define RED_t "\033[31m"
#define YELLOW_t "\033[33m"
#define GREEN_t "\033[32m"
#define WRITE "\033[0m"

#define errorL(msg) \
    std::cout << RED_t <<"Error:["<< __FILE__  << ":"<< __LINE__ << "]:"<< msg << WRITE <<std::endl;
#define debugL(msg) \
    std::cout << YELLOW_t <<"debug:["<< __FILE__ << ":"<< __LINE__ << "]:"<< msg << WRITE << std::endl;
#define infoL(msg) \
    std::cout << GREEN_t <<"infor:["<< __FILE__ << ":" << __LINE__ << "]:"<< msg << WRITE << std::endl;

std::string GetErrorStr() {
    unsigned long er = 0;

    char erbuf[512] = {0};

    size_t erlen = 512;

    er = ERR_get_error();
    ERR_error_string_n(er, erbuf, erlen);
    return std::string(erbuf, erlen);
}

#endif //ECC_PROJECT_INC_H
