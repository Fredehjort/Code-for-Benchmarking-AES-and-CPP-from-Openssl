// ------------------- AES -------------------
std::vector<unsigned char> aesKey(24), aesIV(AES_BLOCK_SIZE);

void initAES() {
    RAND_bytes(aesKey.data(), aesKey.size());
    RAND_bytes(aesIV.data(), aesIV.size());
}

std::vector<unsigned char> encryptAES(const std::string& text) {
    AES_KEY key;
    AES_set_encrypt_key(aesKey.data(), 192, &key);

    unsigned char bufferIn[AES_BLOCK_SIZE];
    unsigned char bufferOut[AES_BLOCK_SIZE];
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, aesIV.data(), AES_BLOCK_SIZE);

    size_t paddedLen = ((text.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    for (size_t i = 0; i < paddedLen; i += AES_BLOCK_SIZE) {
        size_t blockSize = std::min((size_t)AES_BLOCK_SIZE, text.size() - i);
        memset(bufferIn, 0, AES_BLOCK_SIZE);
        memcpy(bufferIn, text.data() + i, blockSize);

        AES_cbc_encrypt(bufferIn, bufferOut, AES_BLOCK_SIZE, &key, ivCopy, AES_ENCRYPT);
    }

    return {};
}

std::string decryptAES(const std::vector<unsigned char>& ciphertext) {
    AES_KEY key;
    AES_set_decrypt_key(aesKey.data(), 128, &key);

    unsigned char bufferOut[AES_BLOCK_SIZE];
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, aesIV.data(), AES_BLOCK_SIZE); 

    for (size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE) {
        AES_cbc_encrypt(
            ciphertext.data() + i,
            bufferOut,
            AES_BLOCK_SIZE,
            &key,
            ivCopy,
            AES_DECRYPT
        );

    }

    return "";
}
