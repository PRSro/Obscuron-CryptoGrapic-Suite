#ifndef DETECTOR_H
#define DETECTOR_H

#include <string>
#include <vector>

struct CipherCandidate {
    std::string cipher_name;
    std::string decrypted;
    std::string key;
    double confidence;
};

std::vector<CipherCandidate> detect_cipher(const std::string &input, int top_n);
double score_english(const std::string &text);
double compute_entropy(const std::string &input);
double compute_ioc(const std::string &input);
std::string sniff_encoding(const std::string &input);

#endif
