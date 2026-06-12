#include "../includes/detector.h"
#include "../includes/basic_ciphers.h"
#include "../includes/historical_ciphers.h"
#include "../includes/essential_ciphers.h"
#include "../includes/bruteforce_ciphers.h"
#include "../includes/standard_ciphers.h"
#include <cctype>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <cstring>

static const double ENG_FREQ[26] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
};

static double chi_sq_to_confidence(double chi_sq) {
    if (chi_sq < 0.0) chi_sq = 0.0;
    if (chi_sq <= 10.0) return 0.9 + 0.1 * (1.0 - chi_sq / 10.0);
    if (chi_sq <= 50.0) return 0.5 + 0.4 * (1.0 - (chi_sq - 10.0) / 40.0);
    if (chi_sq <= 200.0) return 0.1 + 0.4 * (1.0 - (chi_sq - 50.0) / 150.0);
    double v = 0.1 * (1.0 - (chi_sq - 200.0) / 800.0);
    return v < 0.0 ? 0.0 : v;
}

double score_english(const std::string &text) {
    int counts[26] = {0};
    int total = 0;
    for (unsigned char ch : text) {
        if (ch >= 'A' && ch <= 'Z') { counts[ch - 'A']++; total++; }
        else if (ch >= 'a' && ch <= 'z') { counts[ch - 'a']++; total++; }
    }
    if (total == 0) return 999999.0;
    double chi_sq = 0.0;
    for (int i = 0; i < 26; i++) {
        double observed = (100.0 * counts[i]) / total;
        double diff = observed - ENG_FREQ[i];
        chi_sq += (diff * diff) / ENG_FREQ[i];
    }
    return chi_sq;
}

double compute_entropy(const std::string &input) {
    if (input.empty()) return 0.0;
    int counts[256] = {0};
    for (unsigned char ch : input) counts[ch]++;
    double entropy = 0.0;
    double len = (double)input.size();
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = counts[i] / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

double compute_ioc(const std::string &input) {
    int counts[26] = {0};
    int total = 0;
    for (unsigned char ch : input) {
        if (ch >= 'A' && ch <= 'Z') { counts[ch - 'A']++; total++; }
        else if (ch >= 'a' && ch <= 'z') { counts[ch - 'a']++; total++; }
    }
    if (total <= 1) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < 26; i++) sum += counts[i] * (counts[i] - 1.0);
    return sum / (total * (total - 1.0));
}

std::string sniff_encoding(const std::string &input) {
    if (input.empty()) return "text";
    bool high_byte = false;
    for (unsigned char ch : input) {
        if (ch > 0x7E) { high_byte = true; break; }
    }
    if (high_byte) return "binary";
    std::string clean;
    for (unsigned char ch : input) {
        if (!std::isspace(ch)) clean += ch;
    }
    if (clean.empty()) return "text";
    bool all_hex = true;
    for (unsigned char ch : clean) {
        if (!std::isxdigit(ch)) { all_hex = false; break; }
    }
    if (all_hex && (clean.size() % 2 == 0)) return "hex";
    bool all_b64 = true;
    for (unsigned char ch : clean) {
        if (!std::isalnum(ch) && ch != '+' && ch != '/' && ch != '=') {
            all_b64 = false; break;
        }
    }
    if (all_b64 && (clean.size() % 4 == 0)) return "base64";
    return "text";
}

static std::string hex_decode(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s) {
        if (!std::isspace(ch)) clean += ch;
    }
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

static std::string base64_decode(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s) {
        if (!std::isspace(ch) && ch != '=') clean += ch;
    }
    std::string out;
    size_t i = 0;
    for (; i + 3 < clean.size(); i += 4) {
        int v[4] = {b64_val(clean[i]), b64_val(clean[i+1]), b64_val(clean[i+2]), b64_val(clean[i+3])};
        out += (char)((v[0] << 2) | (v[1] >> 4));
        if (v[2] >= 0) out += (char)((v[1] << 4) | (v[2] >> 2));
        if (v[3] >= 0) out += (char)((v[2] << 6) | v[3]);
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

static std::string base32_decode(const std::string &s) {
    const char *b32alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string clean;
    for (unsigned char ch : s) {
        if (!std::isspace(ch) && ch != '=') clean += (char)std::toupper(ch);
    }
    std::string out;
    for (size_t i = 0; i + 7 < clean.size(); i += 8) {
        int v[8];
        for (int j = 0; j < 8; j++) {
            const char *p = strchr(b32alpha, clean[i + j]);
            v[j] = p ? (int)(p - b32alpha) : 0;
        }
        out += (char)((v[0] << 3) | (v[1] >> 2));
        out += (char)((v[1] << 6) | (v[2] << 1) | (v[3] >> 4));
        out += (char)((v[3] << 4) | (v[4] >> 1));
        out += (char)((v[4] << 7) | (v[5] << 2) | (v[6] >> 3));
        out += (char)((v[6] << 5) | v[7]);
    }
    return out;
}

std::vector<CipherCandidate> detect_cipher(const std::string &input, int top_n) {
    std::vector<CipherCandidate> candidates;

    double entropy = compute_entropy(input);
    double ioc = compute_ioc(input);
    std::string encoding = sniff_encoding(input);

    if (entropy > 7.5) {
        CipherCandidate c;
        c.cipher_name = "high-entropy";
        c.decrypted = input;
        c.confidence = 0.1;
        candidates.push_back(c);
        return candidates;
    }

    std::string decoded_input = input;
    if (encoding == "hex") {
        decoded_input = hex_decode(input);
        CipherCandidate c;
        c.cipher_name = "hex";
        c.decrypted = decoded_input;
        c.confidence = 0.7;
        candidates.push_back(c);
    } else if (encoding == "base64") {
        std::string b64dec = base64_decode(input);
        CipherCandidate c;
        c.cipher_name = "base64";
        c.decrypted = b64dec;
        c.confidence = 0.7;
        candidates.push_back(c);
        std::string b32dec = base32_decode(input);
        double b32score = score_english(b32dec);
        CipherCandidate b32c;
        b32c.cipher_name = "base32";
        b32c.decrypted = b32dec;
        b32c.confidence = chi_sq_to_confidence(b32score);
        candidates.push_back(b32c);
    }

    if (ioc > 0.060) {
        std::string mapping, solved;
        substitution_solve(decoded_input, solved, mapping);
        double score = score_english(solved);
        CipherCandidate c;
        c.cipher_name = "substitution";
        c.decrypted = solved;
        c.key = mapping;
        c.confidence = chi_sq_to_confidence(score);
        candidates.push_back(c);
    }

    if (ioc >= 0.040 && ioc <= 0.060) {
        std::vector<std::string> vigenere_results = brute_vigenere_keylength(decoded_input, 8);
        for (size_t i = 0; i < vigenere_results.size(); i++) {
            double score = score_english(vigenere_results[i]);
            CipherCandidate c;
            c.cipher_name = "vigenere";
            c.decrypted = vigenere_results[i];
            c.confidence = chi_sq_to_confidence(score);
            candidates.push_back(c);
        }
    }

    {
        std::vector<std::string> caesar_results = brute_caesar_all(decoded_input);
        for (size_t i = 0; i < caesar_results.size(); i++) {
            double score = score_english(caesar_results[i]);
            CipherCandidate c;
            c.cipher_name = "caesar";
            c.decrypted = caesar_results[i];
            c.key = std::to_string((int)i + 1);
            c.confidence = chi_sq_to_confidence(score);
            candidates.push_back(c);
        }
    }

    {
        std::string out;
        rot13(decoded_input, out);
        double score = score_english(out);
        CipherCandidate c;
        c.cipher_name = "rot13";
        c.decrypted = out;
        c.confidence = chi_sq_to_confidence(score);
        candidates.push_back(c);
    }

    {
        std::string out;
        rot47(decoded_input, out);
        double score = score_english(out);
        CipherCandidate c;
        c.cipher_name = "rot47";
        c.decrypted = out;
        c.confidence = chi_sq_to_confidence(score);
        candidates.push_back(c);
    }

    {
        std::string out;
        atbash(decoded_input, out);
        double score = score_english(out);
        CipherCandidate c;
        c.cipher_name = "atbash";
        c.decrypted = out;
        c.confidence = chi_sq_to_confidence(score);
        candidates.push_back(c);
    }

    char separators[] = {' ', '-', ','};
    for (int si = 0; si < 3; si++) {
        std::string out;
        a1z26(decoded_input, out, separators[si]);
        double score = score_english(out);
        CipherCandidate c;
        c.cipher_name = "a1z26";
        c.decrypted = out;
        c.key = std::string(1, separators[si]);
        c.confidence = chi_sq_to_confidence(score);
        candidates.push_back(c);
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const CipherCandidate &a, const CipherCandidate &b) {
            return a.confidence > b.confidence;
        });

    if (top_n <= 0) top_n = 3;
    if ((size_t)top_n < candidates.size())
        candidates.resize(top_n);

    return candidates;
}
