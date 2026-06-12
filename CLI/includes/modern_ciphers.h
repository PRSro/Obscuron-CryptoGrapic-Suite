#ifndef MODERN_CIPHERS_H
#define MODERN_CIPHERS_H

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

// Hashes
std::string base64_encode(const std::string &in);
std::string base64_decode(const std::string &in);
std::string base64url_encode(const std::string &in);
std::string base64url_decode(const std::string &in);
std::string to_hex(const unsigned char *data, size_t len);
std::string from_hex(const std::string &hex);

void md5_hash(const std::string &input, std::string &output);


void sha1_hash(const std::string &input, std::string &output);
void sha256_hash(const std::string &input, std::string &output);
void sha512_hash(const std::string &input, std::string &output);
void blake2b_hash(const std::string &input, std::string &output, const std::string &key = "");
void blake2s_hash(const std::string &input, std::string &output, const std::string &key = "");

// HMAC
void hmac_sha256(const std::string &input, const std::string &key, std::string &output);
void hmac_sha512(const std::string &input, const std::string &key, std::string &output);

// Key Derivation Functions
void pbkdf2_sha256(const std::string &password, const std::string &salt, uint32_t iterations, uint32_t key_len, std::string &output);
bool argon2id_hash(const std::string &password, const std::string &salt, uint32_t iterations, uint32_t memory_kb, uint32_t parallelism, uint32_t key_len, std::string &output);

// Symmetric Ciphers
// Mode: 0=ECB, 1=CBC, 2=CTR
bool aes_encrypt(const std::string &plaintext, const std::string &key, const std::string &iv, int mode, std::string &ciphertext);
bool aes_decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv, int mode, std::string &plaintext);

void chacha20_crypt(const std::string &input, const std::string &key, const std::string &nonce, uint32_t counter, std::string &output);
void poly1305_mac(const std::string &input, const std::string &key, std::string &mac);

// JWT (JSON Web Tokens)
struct JwtToken {
    std::string header;
    std::string payload;
    std::string signature;
    bool signature_valid;
};
JwtToken jwt_parse(const std::string &token, const std::string &key = "");
std::string jwt_sign(const std::string &header_json, const std::string &payload_json, const std::string &key);

// QR Code generation (basic matrix generator)
std::vector<std::vector<bool>> generate_qr_matrix(const std::string &text);

// Steganography
// Encodes text into carrier BMP/PNG (represented by raw RGBA/RGB bytes or just a simplified LSB operation on string data)
bool lsb_extract(const std::string &carrier_data, std::string &extracted_text);
bool lsb_embed(const std::string &carrier_data, const std::string &text_to_embed, std::string &stego_data);

#endif // MODERN_CIPHERS_H
