#ifndef OUTDATED_CIPHERS_H
#define OUTDATED_CIPHERS_H

#include <string>
#include <vector>
#include <utility>

void rc4(const std::string &input, std::string &out, const std::string &key);

void des_ecb(const std::string &input, std::string &out, const std::string &key, bool encrypt);

void des3_ecb(const std::string &input, std::string &out, const std::string &key, bool encrypt);

void blowfish_ecb(const std::string &input, std::string &out, const std::string &key, bool encrypt);

void vigenere_autokey_broken(const std::string &a, const std::string &key, std::string &out, bool encrypt);

void enigma(const std::string &input, std::string &out, const std::vector<int> &rotors, const std::vector<int> &offsets, const std::vector<std::pair<int,int>> &plugboard);

#endif
