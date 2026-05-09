#ifndef BASIC_H
#define BASIC_H

#include <string>
#include <iostream>

extern const char padding;
extern const std::string alphabet;
extern const std::string alphalphabet;
extern const std::string alphabet_to_morse;
extern const std::string morse_to_alphabet[38];
extern const std::string braille_alphabet;
extern const std::string braille_map[28];
extern const std::string digit_map[10];
extern const std::string NUMBER_INDICATOR;
extern const std::string LETTER_INDICATOR;

void split(const std::string &a, std::string &out);
void parser(const std::string &a, std::string &out);
void reverser(const std::string &a, std::string &out);
int  deconvert_pair(const std::string &pair, int base);
void base_convert(long long b, std::string &out, int base);
void base_deconvert(const std::string &a, long long &b, int base);
void raw_bytes_print(const std::string &a);
void suggestions();
void large_encrypt(const std::string &a, std::string &out, int base);
void large_decrypt(const std::string &a, std::string &out, int base);
void hex_xor(const std::string &a, unsigned char key, std::string &out);
void custom_rot(std::string &a, int add, std::string &out);
void atbash(std::string &a, std::string &out);
void vigenere(const std::string &a, const std::string &key, std::string &out, bool encrypt);
void railfence(const std::string &a, std::string &out, int key, int offset);
void str_xor(const std::string &a, const std::string &b, std::string &out);
void urlcode(const std::string &a, std::string &out, bool encrypt);
void beaufort(const std::string &a, const std::string &key, std::string &out);
void rot13(std::string &a, std::string &out);
void caesar(std::string &a, std::string &out);
void octal(const std::string &a, std::string &out, bool encrypt);
void binary(const std::string &a, std::string &out, bool encrypt);
void morse_encode(std::string a, std::string &out);
void morse_decode(std::string a, std::string &out);
void braille_to_dots(const std::string &cell, std::string &out);
void braille_print_dots(const std::string &a);
void simple_dots_to_braille(const std::string &dots, std::string &out);
void braille_to_simple_dots(const std::string &cell, std::string &out);
void braille_encode(std::string a, std::string &out);
void braille_decode(std::string a, std::string &out);
void columnar_encrypt(const std::string &a, std::string &out, const std::string &key);
void columnar_decrypt(const std::string &a, std::string &out, const std::string &key);
void codepoint_to_utf8(unsigned int cp, std::string &out);
unsigned int utf8_to_codepoint(const std::string &a, int &i);
unsigned int rot8000_cp(unsigned int cp, int key, bool encrypt);
void rot8000(const std::string &a, std::string &out, int key, bool encrypt);
void little_endian_encode(long long val, std::string &out, int bytes);
void big_endian_encode(long long val, std::string &out, int bytes);
void little_endian_decode(const std::string &a, long long &out);
void big_endian_decode(const std::string &a, long long &out);
void a1z26(const std::string &a, std::string &out);

#endif // BASIC_H
