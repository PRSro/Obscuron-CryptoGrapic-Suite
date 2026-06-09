#ifndef ESSENTIAL_CIPHERS_H
#define ESSENTIAL_CIPHERS_H

#include <string>
#include "basic_ciphers.h"

void raw_bytes_print(const std::string &a);
void large_encrypt(const std::string &a, std::string &out, int base);
void large_decrypt(const std::string &a, std::string &out, int base);
void hex_xor(const std::string &a, unsigned char key, std::string &out);
void str_xor(const std::string &a, const std::string &b, std::string &out);
void urlcode(const std::string &a, std::string &out, bool encrypt);

void codepoint_to_utf8(unsigned int cp, std::string &out);
unsigned int utf8_to_codepoint(const std::string &a, int &i);
unsigned int rot8000_cp(unsigned int cp, int key, bool encrypt);
void rot8000(const std::string &a, std::string &out, int key, bool encrypt);

void octal(const std::string &a, std::string &out, bool encrypt);
void binary(const std::string &a, std::string &out, bool encrypt);

#endif
