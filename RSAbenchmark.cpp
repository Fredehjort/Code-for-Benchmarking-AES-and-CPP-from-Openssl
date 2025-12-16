// ------------------- RSA -------------------
RSA* rsaKey = nullptr;

void initRSA() {
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4); // exponent 65537 for at opfylde standard
    rsaKey = RSA_new();
    RSA_generate_key_ex(rsaKey, 4096, bn, nullptr);
    BN_free(bn);
}

std::vector<unsigned char> encryptRSA(const std::string& text) {
    std::vector<unsigned char> encrypted(RSA_size(rsaKey));
    int len = RSA_public_encrypt(
        text.size(),
        reinterpret_cast<const unsigned char*>(text.c_str()),
        encrypted.data(),
        rsaKey,
        RSA_PKCS1_OAEP_PADDING
    );
    if (len == -1) ERR_print_errors_fp(stderr);
    return encrypted;
}

std::string decryptRSA(const std::vector<unsigned char>& encrypted) {
    std::vector<unsigned char> decrypted(RSA_size(rsaKey));
    int len = RSA_private_decrypt(
        encrypted.size(),
        encrypted.data(),
        decrypted.data(),
        rsaKey,
        RSA_PKCS1_OAEP_PADDING
    );

    if (len == -1) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    return std::string(reinterpret_cast<char*>(decrypted.data()), len);
}
