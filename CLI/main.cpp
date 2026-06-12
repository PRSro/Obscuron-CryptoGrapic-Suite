#include "includes/detector.h"
#include "includes/basic_ciphers.h"
#include "includes/historical_ciphers.h"
#include "includes/essential_ciphers.h"
#include "includes/standard_ciphers.h"
#include "includes/outdated_ciphers.h"
#include "includes/bruteforce_ciphers.h"
#include "includes/bytes.h"
#include "includes/modern_ciphers.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>


static void die(const char *msg) {
    std::cerr << "ob-crypt: " << msg << std::endl;
    exit(1);
}

static std::string read_file(const std::string &path) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) {
        std::cerr << "ob-crypt: cannot open '" << path << "'" << std::endl;
        exit(1);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string read_stdin() {
    std::ostringstream ss;
    ss << std::cin.rdbuf();
    return ss.str();
}

static std::string hex_encode(const std::string &bytes) {
    std::string out;
    for (unsigned char ch : bytes) {
        std::string part;
        base_convert((long long)ch, part, 16);
        if (part.size() == 1) out += '0';
        out += part;
    }
    return out;
}

static std::string hex_decode(const std::string &hex) {
    std::string clean;
    for (unsigned char ch : hex)
        if (!std::isspace(ch)) clean += ch;
    std::string out;
    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        std::string pair = {clean[i], clean[i + 1]};
        long long val;
        base_deconvert(pair, val, 16);
        out += (char)(unsigned char)val;
    }
    return out;
}

static int b64_val(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

static std::string _base64_decode(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s)
        if (!std::isspace(ch) && ch != '=') clean += ch;
    std::string out;
    size_t i = 0;
    for (; i + 3 < clean.size(); i += 4) {
        int v0 = b64_val(clean[i]);
        int v1 = b64_val(clean[i+1]);
        int v2 = b64_val(clean[i+2]);
        int v3 = b64_val(clean[i+3]);
        out += (char)((v0 << 2) | (v1 >> 4));
        if (v2 >= 0) out += (char)((v1 << 4) | (v2 >> 2));
        if (v3 >= 0) out += (char)((v2 << 6) | v3);
    }
    size_t rem = clean.size() - i;
    if (rem >= 2) {
        int v0 = b64_val(clean[i]);
        int v1 = b64_val(clean[i+1]);
        out += (char)((v0 << 2) | (v1 >> 4));
        if (rem >= 3) {
            int v2 = b64_val(clean[i+2]);
            out += (char)((v1 << 4) | (v2 >> 2));
        }
    }
    return out;
}

static std::string format_output(const std::string &data, bool hex_output) {
    if (hex_output) return hex_encode(data);
    return data;
}

void affine(const std::string &a, std::string &out, int ka, int kb, bool encrypt);

int main(int argc, char *argv[]) {
    if (argc < 2) { suggestions(); return 0; }

    bool raw = false, hex_input = false, hex_output = false;
    bool stdin_mode = false;
    std::string input_file;

    std::string mode;
    std::vector<std::string> cipher_args;

    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "--raw") { raw = true; i++; }
        else if (arg == "--hex-input") { hex_input = true; i++; }
        else if (arg == "--hex-output") { hex_output = true; i++; }
        else if (arg == "-f") {
            if (++i >= argc) die("-f requires a file path");
            input_file = argv[i++];
        }
        else if (arg == "-") { stdin_mode = true; i++; }
        else if (arg == "--help" || arg == "-h") { mode = "help"; i++; }
        else if (arg == "--list") { mode = "list"; i++; }
        else if (arg == "detect" && mode.empty()) { mode = "detect"; i++; }
        else if (arg == "analyze" && mode.empty()) { mode = "analyze"; i++; }
        else if (arg == "chain" && mode.empty()) { mode = "chain"; i++; }
        else if (mode.empty()) { mode = arg; i++; }
        else { cipher_args.push_back(arg); i++; }
    }

    if (mode.empty() || mode == "help") { suggestions(); return 0; }

    if (mode == "list") {
        const char *names[] = {
            "a1z26", "adfgvx", "aes-cbc", "aes-ctr", "aes-ecb", "affine",
            "analyze", "argon2id", "atbash", "autokey", "bacon", "base_decode",
            "base_encode", "beaufort", "bifid", "big-endian", "binary",
            "blake2b", "blake2s", "blowfish", "braille", "brute-caesar",
            "brute-railfence", "brute-rotate", "brute-vigenere", "brute-xor",
            "caesar", "chacha20", "chain", "columnar", "custom-rot",
            "des", "des3", "detect", "enigma", "four-square",
            "hex-xor", "hmac-sha256", "hmac-sha512", "keyboard-shift",
            "keyword", "large", "little-endian", "lsb-embed", "lsb-extract",
            "md5", "morse", "octal", "pbkdf2", "playfair", "poly1305",
            "polybius", "proper-base", "qr", "railfence", "rc4", "rot13",
            "rot47", "rot8000", "scytale", "sha1", "sha256", "sha512",
            "str-xor", "substitution", "substitution-solve", "trifid",
            "urlcode", "vigenere", "xor", "jwt-parse", "jwt-sign",
            nullptr
        };
        for (int j = 0; names[j]; j++) std::cout << names[j] << "\n";
        return 0;
    }

    if (mode == "detect") {
        int top_n = 3;
        std::string input;
        int ii = 0;
        while (ii < (int)cipher_args.size()) {
            const std::string &a = cipher_args[ii];
            if (a == "--top") {
                if (++ii >= (int)cipher_args.size()) die("--top requires a number");
                top_n = std::atoi(cipher_args[ii].c_str());
            } else if (a == "-f") {
                if (++ii >= (int)cipher_args.size()) die("-f requires a file path");
                input_file = cipher_args[ii];
            } else {
                input = cipher_args[ii];
            }
            ii++;
        }

        std::string raw_input;
        if (!input_file.empty()) raw_input = read_file(input_file);
        else if (stdin_mode) { raw_input = read_stdin(); if (!raw_input.empty() && raw_input[raw_input.size()-1] == '\n') raw_input.pop_back(); }
        else if (!input.empty()) raw_input = input;
        else die("detect requires input");
        if (hex_input) raw_input = hex_decode(raw_input);

        std::vector<CipherCandidate> results = detect_cipher(raw_input, top_n);

        for (size_t j = 0; j < results.size(); j++) {
            if (raw) {
                std::cout << results[j].cipher_name << "|"
                          << results[j].decrypted << "|"
                          << results[j].key << "|"
                          << results[j].confidence << "\n";
            } else {
                std::cout << results[j].confidence
                          << "  " << results[j].cipher_name;
                if (!results[j].key.empty())
                    std::cout << "  (key: " << results[j].key << ")";
                std::cout << "\n  " << results[j].decrypted << "\n";
            }
        }
        return 0;
    }

    if (mode == "analyze") {
        std::string input;
        int ii = 0;
        while (ii < (int)cipher_args.size()) {
            const std::string &a = cipher_args[ii];
            if (a == "-f") {
                if (++ii >= (int)cipher_args.size()) die("-f requires a file path");
                input_file = cipher_args[ii];
            } else {
                input = cipher_args[ii];
            }
            ii++;
        }
        std::string raw_input;
        if (!input_file.empty()) raw_input = read_file(input_file);
        else if (stdin_mode) { raw_input = read_stdin(); if (!raw_input.empty() && raw_input[raw_input.size()-1] == '\n') raw_input.pop_back(); }
        else if (!input.empty()) raw_input = input;
        else die("analyze requires input");
        if (hex_input) raw_input = hex_decode(raw_input);

        double ioc = compute_ioc(raw_input);
        double entropy = compute_entropy(raw_input);
        std::string encoding = sniff_encoding(raw_input);

        std::cout << "encoding: " << encoding << "\n";
        std::cout << "length: " << raw_input.size() << "\n";
        std::cout << "ioc: " << ioc << "\n";
        std::cout << "entropy: " << entropy << "\n";

        int byte_counts[256] = {0};
        for (unsigned char ch : raw_input) byte_counts[ch]++;
        std::cout << "\nbyte distribution (non-zero):\n";
        for (int b = 0; b < 256; b++) {
            if (byte_counts[b] > 0) {
                if (b >= 32 && b <= 126)
                    std::cout << "  '" << (char)b << "' (0x" << std::hex << b << std::dec << "): " << byte_counts[b] << "\n";
                else
                    std::cout << "  0x" << std::hex << b << std::dec << ": " << byte_counts[b] << "\n";
            }
        }

        std::vector<std::pair<char, double>> freqs;
        frequency_analysis(raw_input, freqs);
        if (!freqs.empty()) {
            std::cout << "\nletter frequencies:\n";
            for (size_t j = 0; j < freqs.size(); j++)
                std::cout << "  " << freqs[j].first << ": " << freqs[j].second << "%\n";
        }
        return 0;
    }

    if (mode == "chain") {
        std::string steps_str;
        bool detect_steps = false;
        int top_n = 3;
        std::string input;
        int ii = 0;
        while (ii < (int)cipher_args.size()) {
            const std::string &a = cipher_args[ii];
            if (a == "--steps") {
                if (++ii >= (int)cipher_args.size()) die("--steps requires a value");
                steps_str = cipher_args[ii];
            } else if (a == "--detect") { detect_steps = true; }
            else if (a == "--top") {
                if (++ii >= (int)cipher_args.size()) die("--top requires a number");
                top_n = std::atoi(cipher_args[ii].c_str());
            } else if (a == "-f") {
                if (++ii >= (int)cipher_args.size()) die("-f requires a file path");
                input_file = cipher_args[ii];
            } else {
                input = cipher_args[ii];
            }
            ii++;
        }
        std::string raw_input;
        if (!input_file.empty()) raw_input = read_file(input_file);
        else if (stdin_mode) { raw_input = read_stdin(); if (!raw_input.empty() && raw_input[raw_input.size()-1] == '\n') raw_input.pop_back(); }
        else if (!input.empty()) raw_input = input;
        else die("chain requires input");

        std::string current = raw_input;

        if (!steps_str.empty()) {
            std::vector<std::string> steps;
            std::stringstream ss(steps_str);
            std::string step;
            while (std::getline(ss, step, ',')) {
                if (!step.empty()) steps.push_back(step);
            }

            for (size_t si = 0; si < steps.size(); si++) {
                const std::string &s = steps[si];
                size_t colon = s.find(':');
                std::string cipher = s.substr(0, colon);
                std::string param;
                if (colon != std::string::npos) param = s.substr(colon + 1);

                if (!raw && !detect_steps)
                    std::cout << "  step " << (si+1) << ": " << cipher;
                if (!param.empty() && !detect_steps)
                    std::cout << ":" << param;
                if (!raw && !detect_steps)
                    std::cout << "\n";

                std::string out;
                if (cipher == "base64") { current = _base64_decode(current); }
                else if (cipher == "base16" || cipher == "hex") { current = hex_decode(current); }
                else if (cipher == "caesar" && !param.empty()) {
                    int shift = std::atoi(param.c_str()) % 26;
                    custom_rot(current, shift, out); current = out;
                }
                else if (cipher == "vigenere" && !param.empty()) {
                    vigenere(current, param, out, false); current = out;
                }
                else if (!raw)
                    std::cerr << "  warning: unknown chain step '" << cipher << "', skipping\n";
            }
        }

        if (detect_steps) {
            std::vector<CipherCandidate> results = detect_cipher(current, top_n);
            for (size_t j = 0; j < results.size(); j++) {
                if (raw)
                    std::cout << results[j].cipher_name << "|" << results[j].decrypted << "|" << results[j].confidence << "\n";
                else
                    std::cout << results[j].confidence << "  " << results[j].cipher_name << "\n  " << results[j].decrypted << "\n";
            }
        } else {
            std::cout << (format_output(current, hex_output));
            if (!raw) std::cout << "\n";
        }
        return 0;
    }

    // --- Cipher mode ---
    std::string input;
    std::vector<std::string> args;
    for (int ii = 0; ii < (int)cipher_args.size(); ii++) {
        const std::string &a = cipher_args[ii];
        if (a == "-f") {
            if (++ii >= (int)cipher_args.size()) die("-f requires a file path");
            input_file = cipher_args[ii];
        } else if (a == "-") {
            stdin_mode = true;
        } else if (a == "--hex-input" || a == "--hex-output" || a == "--raw") {
            continue;
        } else if (a == "-s" || a == "-k" || a == "-a" || a == "-b" || a == "-r" || a == "-o" || a == "-p" || a == "-i" || a == "-t" || a == "-m" || a == "-n") {
            args.push_back(a);
            if (ii + 1 < (int)cipher_args.size())
                args.push_back(cipher_args[++ii]);
        } else if (a == "--len" || a == "--offset" || a == "--top" || a == "--iter" || a == "--mem" || a == "--bits" || a == "--counter" || a == "--secret" || a == "--max") {
            args.push_back(a);
            if (ii + 1 < (int)cipher_args.size())
                args.push_back(cipher_args[++ii]);
        } else if (input.empty() && !a.empty() && a[0] != '-') {
            input = a;
        } else {
            args.push_back(a);
        }
    }

    std::string raw_input;
    if (stdin_mode) {
        raw_input = read_stdin();
        if (!raw_input.empty() && raw_input[raw_input.size()-1] == '\n') raw_input.pop_back();
    } else if (!input_file.empty()) {
        raw_input = read_file(input_file);
    } else if (!input.empty()) {
        raw_input = input;
    } else if (!isatty(0)) {
        raw_input = read_stdin();
        if (!raw_input.empty() && raw_input[raw_input.size()-1] == '\n') raw_input.pop_back();
    } else {
        die("missing input argument");
    }
    if (hex_input) raw_input = hex_decode(raw_input);

    bool decrypt = false;
    int shift = 0, key_int = 0, offset = 0, base = 0, a_val = 0, b_val = 0;
    std::string key_str, hex_key;
    int col_len = 0, iterations = 0, memory_kb = 0, key_len = 0, bits_per_char = 0;
    uint32_t chacha_counter = 0;
    std::string iv_str, salt_str, secret_text;
    std::vector<int> enigma_rotors, enigma_offsets;
    std::vector<std::pair<int,int>> enigma_pb;

    auto find_flag = [&](const std::string &flag, const std::string &desc) -> std::string {
        for (size_t j = 0; j < args.size(); j++) {
            if (args[j] == flag) {
                if (j + 1 < args.size()) return args[j + 1];
                die(std::string("missing value for " + flag).c_str());
            }
        }
        die(std::string(desc + " requires " + flag).c_str());
        return "";
    };

    auto has_flag = [&](const std::string &flag) -> bool {
        for (size_t j = 0; j < args.size(); j++)
            if (args[j] == flag) return true;
        return false;
    };

    auto int_flag = [&](const std::string &flag, const std::string &desc) -> int {
        std::string v = find_flag(flag, desc);
        return std::atoi(v.c_str());
    };

    std::string out;

    if (mode == "caesar") {
        shift = has_flag("-s") ? int_flag("-s", "caesar") : 3;
        custom_rot(raw_input, shift, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "rot13") {
        rot13(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "rot47") {
        rot47(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "vigenere") {
        key_str = find_flag("-k", "vigenere");
        decrypt = has_flag("--decrypt");
        vigenere(raw_input, key_str, out, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "atbash") {
        atbash(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "playfair") {
        key_str = find_flag("-k", "playfair");
        decrypt = has_flag("--decrypt");
        playfair(raw_input, out, key_str, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "affine") {
        a_val = int_flag("-a", "affine");
        b_val = int_flag("-b", "affine");
        decrypt = has_flag("--decrypt");
        affine(raw_input, out, a_val, b_val, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "columnar") {
        key_str = find_flag("-k", "columnar");
        decrypt = has_flag("--decrypt");
        if (has_flag("--len")) col_len = int_flag("--len", "columnar");
        if (decrypt) {
            if (col_len == 0) die("columnar decrypt requires --len <int>");
            columnar_decrypt(raw_input, out, key_str, col_len);
        } else {
            columnar_encrypt(raw_input, out, key_str);
        }
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "railfence") {
        key_int = int_flag("-k", "railfence");
        offset = has_flag("--offset") ? int_flag("--offset", "railfence") : 0;
        railfence(raw_input, out, key_int, offset);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "xor") {
        std::string k = find_flag("-k", "xor");
        std::string key_bytes = hex_decode(k);
        out = raw_input;
        for (size_t j = 0; j < raw_input.size(); j++)
            out[j] = raw_input[j] ^ key_bytes[j % key_bytes.size()];
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "base_encode") {
        base = int_flag("-b", "base_encode");
        large_encrypt(raw_input, out, base);
        std::cout << out;
        if (!raw) std::cout << "\n";
    }
    else if (mode == "base_decode") {
        base = int_flag("-b", "base_decode");
        // normalize case for hex and alphanum bases
        std::string dec_input;
        for (char c : raw_input) dec_input += (char)std::tolower((unsigned char)c);
        large_decrypt(dec_input, out, base);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "rc4") {
        key_str = find_flag("-k", "rc4");
        rc4(raw_input, out, key_str);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "des") {
        hex_key = find_flag("-k", "des");
        std::string key_bytes = hex_decode(hex_key);
        decrypt = has_flag("--decrypt");
        des_ecb(raw_input, out, key_bytes, decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "blowfish") {
        key_str = find_flag("-k", "blowfish");
        decrypt = has_flag("--decrypt");
        blowfish_ecb(raw_input, out, key_str, decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "enigma") {
        std::string rotors_str = find_flag("-r", "enigma");
        std::string off_str = find_flag("-o", "enigma");
        std::stringstream rs(rotors_str);
        std::string token;
        while (std::getline(rs, token, ','))
            enigma_rotors.push_back(std::atoi(token.c_str()));
        std::stringstream os(off_str);
        while (std::getline(os, token, ','))
            enigma_offsets.push_back(std::atoi(token.c_str()));
        if (has_flag("-p")) {
            std::string pb_str = find_flag("-p", "enigma");
            std::stringstream pbs(pb_str);
            std::string pair;
            while (std::getline(pbs, pair, ',')) {
                size_t colon = pair.find(':');
                if (colon != std::string::npos) {
                    int a = std::atoi(pair.substr(0, colon).c_str());
                    int b = std::atoi(pair.substr(colon + 1).c_str());
                    enigma_pb.push_back({a, b});
                }
            }
        }
        enigma(raw_input, out, enigma_rotors, enigma_offsets, enigma_pb);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── Hashes ────────────────────────────────────────────────────────────────
    else if (mode == "md5") {
        md5_hash(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "sha1") {
        sha1_hash(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "sha256") {
        sha256_hash(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "sha512") {
        sha512_hash(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "blake2b") {
        key_str = has_flag("-k") ? find_flag("-k", "blake2b") : "";
        blake2b_hash(raw_input, out, key_str);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "blake2s") {
        key_str = has_flag("-k") ? find_flag("-k", "blake2s") : "";
        blake2s_hash(raw_input, out, key_str);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── HMAC ───────────────────────────────────────────────────────────────────
    else if (mode == "hmac-sha256") {
        key_str = find_flag("-k", "hmac-sha256");
        hmac_sha256(raw_input, key_str, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "hmac-sha512") {
        key_str = find_flag("-k", "hmac-sha512");
        hmac_sha512(raw_input, key_str, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── AES modes ──────────────────────────────────────────────────────────────
    else if (mode == "aes-ecb") {
        hex_key = find_flag("-k", "aes-ecb");
        std::string k = hex_decode(hex_key);
        decrypt = has_flag("--decrypt");
        bool ok;
        if (decrypt)
            ok = aes_decrypt(raw_input, k, "", 0, out);
        else
            ok = aes_encrypt(raw_input, k, "", 0, out);
        if (!ok) die("AES-ECB operation failed (check key size: 16/24/32 bytes hex)");
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "aes-cbc") {
        hex_key = find_flag("-k", "aes-cbc");
        std::string k = hex_decode(hex_key);
        iv_str = find_flag("-i", "aes-cbc");
        std::string iv = hex_decode(iv_str);
        decrypt = has_flag("--decrypt");
        bool ok;
        if (decrypt)
            ok = aes_decrypt(raw_input, k, iv, 1, out);
        else
            ok = aes_encrypt(raw_input, k, iv, 1, out);
        if (!ok) die("AES-CBC operation failed");
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "aes-ctr") {
        hex_key = find_flag("-k", "aes-ctr");
        std::string k = hex_decode(hex_key);
        iv_str = find_flag("-i", "aes-ctr");
        std::string iv = hex_decode(iv_str);
        decrypt = has_flag("--decrypt");
        bool ok;
        if (decrypt)
            ok = aes_decrypt(raw_input, k, iv, 2, out);
        else
            ok = aes_encrypt(raw_input, k, iv, 2, out);
        if (!ok) die("AES-CTR operation failed");
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── ChaCha20 ───────────────────────────────────────────────────────────────
    else if (mode == "chacha20") {
        hex_key = find_flag("-k", "chacha20");
        std::string k = hex_decode(hex_key);
        iv_str = find_flag("-i", "chacha20");
        std::string nonce = hex_decode(iv_str);
        if (has_flag("--counter")) chacha_counter = (uint32_t)int_flag("--counter", "chacha20");
        chacha20_crypt(raw_input, k, nonce, chacha_counter, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── Poly1305 ───────────────────────────────────────────────────────────────
    else if (mode == "poly1305") {
        hex_key = find_flag("-k", "poly1305");
        std::string k = hex_decode(hex_key);
        poly1305_mac(raw_input, k, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── Key Derivation ─────────────────────────────────────────────────────────
    else if (mode == "pbkdf2") {
        salt_str = find_flag("-s", "pbkdf2");
        iterations = int_flag("--iter", "pbkdf2");
        key_len = int_flag("--len", "pbkdf2");
        pbkdf2_sha256(raw_input, salt_str, (uint32_t)iterations, (uint32_t)key_len, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "argon2id") {
        salt_str = find_flag("-s", "argon2id");
        iterations = int_flag("--iter", "argon2id");
        memory_kb = int_flag("--mem", "argon2id");
        key_len = int_flag("--len", "argon2id");
        bool ok = argon2id_hash(raw_input, salt_str, (uint32_t)iterations, (uint32_t)memory_kb, 1, (uint32_t)key_len, out);
        if (!ok) die("argon2id failed");
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── JWT ─────────────────────────────────────────────────────────────────────
    else if (mode == "jwt-sign") {
        key_str = find_flag("-k", "jwt-sign");
        out = jwt_sign(raw_input, raw_input, key_str);
        std::cout << out;
        if (!raw) std::cout << "\n";
    }
    else if (mode == "jwt-parse") {
        key_str = has_flag("-k") ? find_flag("-k", "jwt-parse") : "";
        JwtToken tok = jwt_parse(raw_input, key_str);
        std::cout << "header:  " << tok.header << "\n";
        std::cout << "payload: " << tok.payload << "\n";
        std::cout << "signature: " << tok.signature << "\n";
        std::cout << "valid:   " << (tok.signature_valid ? "yes" : "no") << "\n";
    }

    // ── QR Code ────────────────────────────────────────────────────────────────
    else if (mode == "qr") {
        std::vector<std::vector<bool>> matrix = generate_qr_matrix(raw_input);
        for (size_t y = 0; y < matrix.size(); y++) {
            for (size_t x = 0; x < matrix[y].size(); x++)
                std::cout << (matrix[y][x] ? "##" : "  ");
            std::cout << "\n";
        }
    }

    // ── LSB Steganography ──────────────────────────────────────────────────────
    else if (mode == "lsb-embed") {
        secret_text = find_flag("--secret", "lsb-embed");
        bool ok = lsb_embed(raw_input, secret_text, out);
        if (!ok) die("lsb-embed failed (carrier too small?)");
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "lsb-extract") {
        bool ok = lsb_extract(raw_input, out);
        if (!ok) die("lsb-extract failed (no hidden data found?)");
        std::cout << out;
        if (!raw) std::cout << "\n";
    }

    // ── Classical ciphers (listed but never dispatched) ─────────────────────────
    else if (mode == "autokey") {
        key_str = find_flag("-k", "autokey");
        decrypt = has_flag("--decrypt");
        autokey(raw_input, key_str, out, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "a1z26") {
        std::string sep = has_flag("-s") ? find_flag("-s", "a1z26") : "-";
        a1z26(raw_input, out, sep[0]);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "bacon") {
        decrypt = has_flag("--decrypt");
        bacon(raw_input, out, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "beaufort") {
        key_str = find_flag("-k", "beaufort");
        beaufort(raw_input, key_str, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "bifid") {
        key_str = has_flag("-k") ? find_flag("-k", "bifid") : "ABCDEFGHIKLMNOPQRSTUVWXYZ";
        decrypt = has_flag("--decrypt");
        char grid[6][6]; int row_of[256], col_of[256];
        std::string rows[5];
        for (int r = 0; r < 5; r++) rows[r] = key_str.substr(r * 5, 5);
        build_bifid_grid(rows, grid, row_of, col_of);
        if (decrypt)
            bifid_decrypt(raw_input, out, grid, row_of, col_of);
        else
            bifid_encrypt(raw_input, out, grid, row_of, col_of);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "binary") {
        decrypt = has_flag("--decrypt");
        binary(raw_input, out, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "braille") {
        decrypt = has_flag("--decrypt");
        if (decrypt)
            braille_decode(raw_input, out);
        else
            braille_encode(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "four-square") {
        std::string keys_str = find_flag("-k", "four-square");
        size_t comma = keys_str.find(',');
        std::string k1, k2;
        if (comma != std::string::npos) {
            k1 = keys_str.substr(0, comma);
            k2 = keys_str.substr(comma + 1);
        } else { k1 = k2 = keys_str; }
        decrypt = has_flag("--decrypt");
        four_square(raw_input, out, k1, k2, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "keyboard-shift" || mode == "keyboard_shift") {
        shift = int_flag("-s", "keyboard-shift");
        decrypt = has_flag("--decrypt");
        keyboard_shift(raw_input, out, shift, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "keyword") {
        key_str = find_flag("-k", "keyword");
        decrypt = has_flag("--decrypt");
        keyword_cipher(raw_input, out, key_str, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "morse") {
        decrypt = has_flag("--decrypt");
        if (decrypt)
            morse_decode(raw_input, out);
        else
            morse_encode(raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "octal") {
        decrypt = has_flag("--decrypt");
        octal(raw_input, out, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "polybius") {
        std::string alpha = has_flag("-k") ? find_flag("-k", "polybius") : "ABCDEFGHIKLMNOPQRSTUVWXYZ";
        decrypt = has_flag("--decrypt");
        if (decrypt)
            polybius_decrypt(alpha, raw_input, out);
        else
            polybius_encrypt(alpha, raw_input, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "rot8000") {
        decrypt = has_flag("--decrypt");
        rot8000(raw_input, out, 0, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "scytale") {
        key_int = int_flag("-k", "scytale");
        decrypt = has_flag("--decrypt");
        if (decrypt)
            scytale_decrypt(raw_input, out, key_int);
        else
            scytale_encrypt(raw_input, out, key_int);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "substitution") {
        key_str = find_flag("-k", "substitution");
        decrypt = has_flag("--decrypt");
        if (decrypt)
            substitution_decrypt(raw_input, out, key_str);
        else
            substitution_encrypt(raw_input, out, key_str);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "substitution-solve") {
        std::string mapping;
        substitution_solve(raw_input, out, mapping);
        std::cout << "mapping: " << mapping << "\n";
        std::cout << out;
        if (!raw) std::cout << "\n";
    }
    else if (mode == "trifid") {
        key_str = find_flag("-k", "trifid");
        decrypt = has_flag("--decrypt");
        int period = has_flag("--len") ? int_flag("--len", "trifid") : 5;
        trifid(raw_input, out, key_str, period, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "urlcode") {
        decrypt = has_flag("--decrypt");
        urlcode(raw_input, out, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "adfgvx") {
        std::string keys_str = find_flag("-k", "adfgvx");
        size_t comma = keys_str.find(',');
        std::string poly_key, col_key;
        if (comma != std::string::npos) {
            poly_key = keys_str.substr(0, comma);
            col_key = keys_str.substr(comma + 1);
        } else { poly_key = keys_str; col_key = "ADFGVX"; }
        decrypt = has_flag("--decrypt");
        adfgvx(raw_input, out, poly_key, col_key, !decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "des3") {
        hex_key = find_flag("-k", "des3");
        std::string k = hex_decode(hex_key);
        decrypt = has_flag("--decrypt");
        des3_ecb(raw_input, out, k, decrypt);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "custom-rot" || mode == "custom_rot") {
        shift = int_flag("-s", "custom-rot");
        custom_rot(raw_input, shift, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "hex-xor" || mode == "hex_xor") {
        std::string k = find_flag("-k", "hex-xor");
        unsigned char key_byte = (unsigned char)std::strtol(k.c_str(), NULL, 16);
        hex_xor(raw_input, key_byte, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "str-xor" || mode == "str_xor") {
        key_str = find_flag("-k", "str-xor");
        str_xor(raw_input, key_str, out);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "large") {
        base = int_flag("-b", "large");
        decrypt = has_flag("--decrypt");
        if (decrypt) {
            std::string dec_input;
            for (char c : raw_input) dec_input += (char)std::tolower((unsigned char)c);
            large_decrypt(dec_input, out, base);
        } else {
            large_encrypt(raw_input, out, base);
        }
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    // ── Brute-force ────────────────────────────────────────────────────────────
    else if (mode == "brute-rotate") {
        brute_rotate(raw_input);
        std::cout << raw_input;
        if (!raw) std::cout << "\n";
    }
    else if (mode == "brute-caesar") {
        std::vector<std::string> results = brute_caesar_all(raw_input);
        for (size_t j = 0; j < results.size(); j++)
            std::cout << (j+1) << ": " << results[j] << "\n";
    }
    else if (mode == "brute-railfence") {
        int max_k = has_flag("--max") ? int_flag("--max", "brute-railfence") : 10;
        std::vector<std::string> results = brute_railfence_all(raw_input, max_k);
        for (size_t j = 0; j < results.size(); j++)
            std::cout << (j+1) << ": " << results[j] << "\n";
    }
    else if (mode == "brute-xor") {
        std::vector<std::string> results = brute_xor_single_byte(raw_input);
        for (size_t j = 0; j < results.size(); j++)
            std::cout << (j) << ": " << results[j] << "\n";
    }
    else if (mode == "brute-vigenere") {
        int max_len = has_flag("--max") ? int_flag("--max", "brute-vigenere") : 10;
        std::vector<std::string> results = brute_vigenere_keylength(raw_input, max_len);
        for (size_t j = 0; j < results.size(); j++)
            std::cout << (j+1) << ": " << results[j] << "\n";
    }

    // ── Endian encoding ────────────────────────────────────────────────────────
    else if (mode == "little-endian") {
        long long val = std::atoll(raw_input.c_str());
        int bytes = has_flag("--len") ? int_flag("--len", "little-endian") : 4;
        little_endian_encode(val, out, bytes);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "big-endian") {
        long long val = std::atoll(raw_input.c_str());
        int bytes = has_flag("--len") ? int_flag("--len", "big-endian") : 4;
        big_endian_encode(val, out, bytes);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }
    else if (mode == "proper-base") {
        bits_per_char = int_flag("--bits", "proper-base");
        std::string alphabet = has_flag("-k") ? find_flag("-k", "proper-base") : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        proper_base_convert(raw_input, out, bits_per_char, alphabet);
        std::cout << format_output(out, hex_output);
        if (!raw) std::cout << "\n";
    }

    else {
        std::cerr << "ob-crypt: unknown cipher '" << mode << "'" << std::endl;
        return 1;
    }

    return 0;
}
