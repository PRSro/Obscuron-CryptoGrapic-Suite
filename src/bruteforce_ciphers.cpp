#include "../includes/bruteforce_ciphers.h"

void brute_rotate(std::string &a) {
    std::string out;
    custom_rot(a, 1, out);
    a = out;
}

std::vector<std::string> brute_caesar_all(const std::string &a) {
    std::vector<std::string> results;
    for (int shift = 1; shift < 26; shift++) {
        std::string out;
        custom_rot(const_cast<std::string&>(a), shift, out);
        results.push_back(out);
    }
    return results;
}

std::vector<std::string> brute_railfence_all(const std::string &a, int max_key) {
    std::vector<std::string> results;
    for (int key = 2; key <= max_key; key++) {
        for (int offset = 0; offset < 2*(key-1); offset++) {
            std::string out;
            railfence(a, out, key, offset);
            results.push_back(out);
        }
    }
    return results;
}

std::vector<std::string> brute_xor_single_byte(const std::string &a) {
    std::vector<std::string> results;
    for (int key = 0; key < 256; key++) {
        std::string out;
        str_xor(a, std::string(a.length(), (char)key), out);
        results.push_back(out);
    }
    return results;
}

std::vector<std::string> brute_rot_all(const std::string &a) {
    std::vector<std::string> results;
    for (int shift = 1; shift < 26; shift++) {
        std::string out;
        custom_rot(const_cast<std::string&>(a), shift, out);
        results.push_back(out);
    }
    {
        std::string out;
        rot47(a, out);
        results.push_back(out);
    }
    for (int key : {1, 13, 47, 111, 8000, 65535}) {
        std::string out;
        rot8000(a, out, key, true);
        results.push_back(out);
    }
    return results;
}

std::vector<std::string> brute_vigenere_keylength(const std::string &a, int max_len) {
    std::vector<std::string> results;
    // For each keylength, try to determine the most likely key using Kasiski or frequency
    // For simplicity, return empty strings as placeholders for future implementation
    (void)a;
    results.resize(max_len);
    return results;
}
