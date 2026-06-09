#include "../includes/standard_ciphers.h"
#include "../includes/basic_ciphers.h"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>

static const double ENGLISH_FREQ[26] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
};

void rot47(const std::string &a, std::string &out) {
    out.clear();
    for (unsigned char ch : a) {
        if (ch >= 33 && ch <= 126)
            out += (char)(33 + (ch - 33 + 47) % 94);
        else
            out += ch;
    }
}

void keyword_cipher(const std::string &a, std::string &out, const std::string &keyword, bool encrypt) {
    std::string cipher_alphabet;
    std::set<char> seen;
    for (char ch : keyword) {
        char u = (char)toupper(ch);
        if (u >= 'A' && u <= 'Z' && seen.find(u) == seen.end()) {
            seen.insert(u);
            cipher_alphabet += u;
        }
    }
    for (char ch = 'A'; ch <= 'Z'; ch++) {
        if (seen.find(ch) == seen.end())
            cipher_alphabet += ch;
    }

    out.clear();
    for (unsigned char ch : a) {
        if (ch >= 'A' && ch <= 'Z') {
            if (encrypt)
                out += cipher_alphabet[ch - 'A'];
            else {
                size_t pos = cipher_alphabet.find((char)ch);
                out += (pos != std::string::npos) ? (char)('A' + pos) : ch;
            }
        } else if (ch >= 'a' && ch <= 'z') {
            char upper = (char)toupper(ch);
            char mapped;
            if (encrypt)
                mapped = cipher_alphabet[upper - 'A'];
            else {
                size_t pos = cipher_alphabet.find(upper);
                mapped = (pos != std::string::npos) ? (char)('A' + pos) : upper;
            }
            out += (char)tolower(mapped);
        } else {
            out += ch;
        }
    }
}

void substitution_encrypt(const std::string &a, std::string &out, const std::string &key) {
    out.clear();
    for (unsigned char ch : a) {
        if (ch >= 'A' && ch <= 'Z')
            out += (char)toupper(key[ch - 'A']);
        else if (ch >= 'a' && ch <= 'z')
            out += (char)tolower(key[ch - 'a']);
        else
            out += ch;
    }
}

void substitution_decrypt(const std::string &a, std::string &out, const std::string &key) {
    std::string reverse(26, ' ');
    for (int i = 0; i < 26; i++)
        reverse[toupper(key[i]) - 'A'] = (char)('A' + i);

    out.clear();
    for (unsigned char ch : a) {
        if (ch >= 'A' && ch <= 'Z')
            out += reverse[ch - 'A'];
        else if (ch >= 'a' && ch <= 'z')
            out += (char)tolower(reverse[toupper(ch) - 'A']);
        else
            out += ch;
    }
}

void frequency_analysis(const std::string &a, std::vector<std::pair<char, double>> &freqs) {
    freqs.clear();
    int counts[26] = {0};
    int total = 0;

    for (unsigned char ch : a) {
        if (ch >= 'A' && ch <= 'Z') { counts[ch - 'A']++; total++; }
        else if (ch >= 'a' && ch <= 'z') { counts[ch - 'a']++; total++; }
    }

    if (total == 0) return;

    for (int i = 0; i < 26; i++)
        freqs.push_back({(char)('A' + i), 100.0 * counts[i] / total});

    std::sort(freqs.begin(), freqs.end(),
        [](const std::pair<char,double> &a, const std::pair<char,double> &b) {
            return a.second > b.second;
        });
}

void substitution_solve(const std::string &a, std::string &out, std::string &mapping) {
    const char english_order[26] = {
        'E','T','A','O','I','N','S','H','R','D','L','C','U',
        'M','W','F','G','Y','P','B','V','K','J','X','Q','Z'
    };

    std::vector<std::pair<char, double>> freqs;
    frequency_analysis(a, freqs);

    mapping = std::string(26, ' ');
    for (size_t i = 0; i < freqs.size() && i < 26; i++)
        mapping[freqs[i].first - 'A'] = english_order[i];

    substitution_decrypt(a, out, mapping);
}

double index_of_coincidence(const std::string &a) {
    int counts[26] = {0};
    int total = 0;

    for (unsigned char ch : a) {
        if (ch >= 'A' && ch <= 'Z') { counts[ch - 'A']++; total++; }
        else if (ch >= 'a' && ch <= 'z') { counts[ch - 'a']++; total++; }
    }

    if (total <= 1) return 0.0;

    double sum = 0.0;
    for (int i = 0; i < 26; i++)
        sum += counts[i] * (counts[i] - 1.0);

    return sum / (total * (total - 1.0));
}

void find_key_lengths(const std::string &a, std::vector<int> &lengths, int max_len) {
    lengths.clear();
    if (a.length() < 6) return;

    std::map<std::string, std::vector<int>> trigram_positions;

    for (size_t i = 0; i + 2 < a.length(); i++) {
        std::string tri;
        for (int j = 0; j < 3; j++) {
            char ch = (char)toupper(a[i + j]);
            if (ch >= 'A' && ch <= 'Z') tri += ch;
            else break;
        }
        if (tri.length() == 3)
            trigram_positions[tri].push_back((int)i);
    }

    std::map<int, int> divisor_counts;
    for (auto &entry : trigram_positions) {
        auto &pos = entry.second;
        for (size_t i = 0; i + 1 < pos.size(); i++) {
            int dist = pos[i + 1] - pos[i];
            if (dist <= 1) continue;
            for (int d = 2; d <= max_len && d <= dist; d++) {
                if (dist % d == 0)
                    divisor_counts[d]++;
            }
        }
    }

    std::vector<std::pair<int, int>> sorted;
    for (auto &entry : divisor_counts)
        sorted.push_back(entry);

    std::sort(sorted.begin(), sorted.end(),
        [](const std::pair<int,int> &a, const std::pair<int,int> &b) {
            return a.second > b.second;
        });

    for (auto &entry : sorted)
        lengths.push_back(entry.first);
}

void rc4(const std::string &input, std::string &out, const std::string &key) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + (unsigned char)key[i % key.size()]) & 0xFF;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    out = input;
    int i = 0;
    j = 0;
    for (size_t n = 0; n < input.size(); n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        out[n] = (unsigned char)(input[n] ^ S[(S[i] + S[j]) & 0xFF]);
    }
}
