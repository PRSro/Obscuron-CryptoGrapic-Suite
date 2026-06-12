#include "../includes/bruteforce_ciphers.h"
#include <cctype>
#include <cmath>

void brute_rotate(std::string &a) {
    std::string out;
    custom_rot(a, 1, out);
    a = out;
}

std::vector<std::string> brute_caesar_all(const std::string &a) {
    std::vector<std::string> results;
    for (int shift = 1; shift < 26; shift++) {
        std::string out;
        custom_rot(a, shift, out);
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
        custom_rot(a, shift, out);
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
    std::vector<int> lengths;
    find_key_lengths(a, lengths, max_len);
    if (lengths.empty()) {
        for (int len = 2; len <= max_len; len++)
            lengths.push_back(len);
    }
    static const double eng_freq[26]={
        8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
        6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
        0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
        1.974, 0.074
    };
    double eng_sum = 0;
    for (int i = 0; i < 26; i++) eng_sum += eng_freq[i];
    double eng_prob[26];
    for (int i = 0; i < 26; i++) eng_prob[i] = eng_freq[i] / eng_sum;
    for (int keylen : lengths) {
        if (keylen < 2 || keylen > max_len) continue;
        std::string clean;
        for (char c : a) {
            if (c >= 'a' && c <= 'z') clean += c;
            else if (c >= 'A' && c <= 'Z') clean += (char)(c - 'A' + 'a');
        }
        if ((int)clean.length() < keylen * 2) continue;
        std::string key;
        for (int pos = 0; pos < keylen; pos++) {
            int counts[26] = {0};
            int total = 0;
            for (int j = pos; j < (int)clean.length(); j += keylen) {
                counts[clean[j] - 'a']++;
                total++;
            }
            if (total == 0) { key += 'a'; continue; }
            double best_score = -1e9;
            int best_shift = 0;
            for (int shift = 0; shift < 26; shift++) {
                double score = 0.0;
                for (int pt = 0; pt < 26; pt++) {
                    int ct = (pt + shift) % 26;
                    score += eng_prob[pt] * counts[ct];
                }
                if (score > best_score) {
                    best_score = score;
                    best_shift = shift;
                }
            }
            key+=(char)('a'+best_shift);
        }
        std::string out;
        vigenere(a, key, out, false);
        results.push_back(out);
    }
    return results;
}
