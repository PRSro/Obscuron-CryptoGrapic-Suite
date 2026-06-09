#include "../includes/bytes.h"
#include "../includes/basic_ciphers.h"
#include <cstdio>
#include <cctype>

void little_endian_encode(long long val, std::string &out, int bytes) {
    out = "";
    for (int i = 0; i < bytes; i++) {
        std::string part;
        base_convert((long long)(val & 0xFF), part, 16);
        if ((int)part.length() < 2) part = "0" + part;
        out += part + " ";
        val >>= 8;
    }
}

void big_endian_encode(long long val, std::string &out, int bytes) {
    out = "";
    std::string temp = "";
    long long v = val;
    for (int i = 0; i < bytes; i++) {
        std::string part;
        base_convert((long long)(v & 0xFF), part, 16);
        if ((int)part.length() < 2) part = "0" + part;
        temp = part + " " + temp;
        v >>= 8;
    }
    out = temp;
}

void little_endian_decode(const std::string &a, long long &out) {
    out = 0;
    std::string token;
    int shift = 0;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            long long byte_val;
            base_deconvert(token, byte_val, 16);
            out |= (byte_val << shift);
            shift += 8;
            token = "";
        } else {
            token += c;
        }
    }
}

void big_endian_decode(const std::string &a, long long &out) {
    out = 0;
    std::vector<std::string> tokens;
    std::string t;
    for (char c : a + " ") {
        if (c == ' ') {
            if (t.empty()) continue;
            tokens.push_back(t);
            t = "";
        } else {
            t += c;
        }
    }
    for (size_t i = 0; i < tokens.size(); i++) {
        long long byte_val;
        base_deconvert(tokens[i], byte_val, 16);
        out = (out << 8) | byte_val;
    }
}

void proper_base_convert(const std::string &input, std::string &out, int bits_per_char, const std::string &alphabet) {
    out.clear();
    if (input.empty() || bits_per_char < 1 || bits_per_char > 7) return;

    int mask = (1 << bits_per_char) - 1;
    unsigned long long buffer = 0;
    int bits_in_buffer = 0;

    for (unsigned char byte : input) {
        buffer = (buffer << 8) | byte;
        bits_in_buffer += 8;

        while (bits_in_buffer >= bits_per_char) {
            bits_in_buffer -= bits_per_char;
            int idx = (buffer >> bits_in_buffer) & mask;
            out += alphabet[idx];
        }
    }

    if (bits_in_buffer > 0) {
        buffer <<= (bits_per_char - bits_in_buffer);
        int idx = buffer & mask;
        out += alphabet[idx];
    }

    // padding: align to natural group boundary
    int a = 8, b = bits_per_char, g = 1;
    for (int i = 1; i <= a && i <= b; i++)
        if (a % i == 0 && b % i == 0) g = i;
    int chars_per_group = a / g;

    int pad = chars_per_group - (out.size() % chars_per_group);
    if (pad != chars_per_group)
        out.append(pad, '=');
}
