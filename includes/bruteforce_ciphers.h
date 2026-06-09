#ifndef BRUTEFORCE_CIPHERS_H
#define BRUTEFORCE_CIPHERS_H

#include <string>
#include <vector>
#include "basic_ciphers.h"
#include "historical_ciphers.h"
#include "essential_ciphers.h"
#include "standard_ciphers.h"

void brute_rotate(std::string &a);
std::vector<std::string> brute_rot_all(const std::string &a);
std::vector<std::string> brute_caesar_all(const std::string &a);
std::vector<std::string> brute_railfence_all(const std::string &a, int max_key);
std::vector<std::string> brute_xor_single_byte(const std::string &a);
std::vector<std::string> brute_vigenere_keylength(const std::string &a, int max_len);

#endif
