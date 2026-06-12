#ifndef BYTES_H
#define BYTES_H

#include <string>
#include <vector>

void little_endian_encode(long long val, std::string &out, int bytes);
void big_endian_encode(long long val, std::string &out, int bytes);
void little_endian_decode(const std::string &a, long long &out);
void big_endian_decode(const std::string &a, long long &out);

// Chunk-oriented base encoding on raw bytes (not big-integer based).
// Preserves leading zeros — unlike base_convert which treats the whole input as one number.
// bits_per_char: 6 for base64, 5 for base32, 4 for hex, 3 for octal, etc.
// alphabet must have exactly 2^bits_per_char entries.
// Output is padded with '=' to align to the natural group boundary.
void proper_base_convert(const std::string &input, std::string &out, int bits_per_char, const std::string &alphabet);

#endif
