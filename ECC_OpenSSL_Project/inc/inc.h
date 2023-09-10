#ifndef BPIR_ECDH_H
#define BPIR_ECDH_H
#include <openssl/pem.h>
#include <openssl/ecdh.h>
#include <iostream>
#include <sstream>
#include <vector>

namespace aes{}

class myECC {
public:
    void encrypt(std::string key, std::vector<std::string> &plaintext, std::vector<std::string> &strCipher_list, unsigned long long size,  int div = 0);
    void decrypt(std::string key, std::vector<std::string> &plaintext, std::vector<std::string> &strCipher_list, unsigned long long size,  int div = 0);
};


#endif //BPIR_ECDH_H
