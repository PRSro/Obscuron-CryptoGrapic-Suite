#ifndef STANDARD_CIPHERS_H
#define STANDARD_CIPHERS_H

#include <string>
#include <vector>
#include <utility>

void rot47(const std::string &a, std::string &out);

void keyword_cipher(const std::string &a, std::string &out, const std::string &keyword, bool encrypt);

void substitution_encrypt(const std::string &a, std::string &out, const std::string &key);
void substitution_decrypt(const std::string &a, std::string &out, const std::string &key);

void frequency_analysis(const std::string &a, std::vector<std::pair<char, double>> &freqs);
void substitution_solve(const std::string &a, std::string &out, std::string &mapping);

double index_of_coincidence(const std::string &a);
void find_key_lengths(const std::string &a, std::vector<int> &lengths, int max_len = 20);

#endif
