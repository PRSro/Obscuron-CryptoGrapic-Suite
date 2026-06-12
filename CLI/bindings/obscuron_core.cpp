#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
namespace py = pybind11;

#include "../includes/basic_ciphers.h"
#include "../includes/historical_ciphers.h"
#include "../includes/essential_ciphers.h"
#include "../includes/bytes.h"
#include "../includes/standard_ciphers.h"
#include "../includes/outdated_ciphers.h"
#include "../includes/bruteforce_ciphers.h"

PYBIND11_MODULE(_obscuron_core, m) {
    m.doc() = "Obscuron Crypto Suite — C++ accelerated cipher library";

    // ── basic_ciphers ──

    m.def("split", [](const std::string &a) {
        std::string out; split(a, out); return out;
    });
    m.def("parser", [](const std::string &a) {
        std::string out; parser(a, out); return out;
    });
    m.def("reverser", [](const std::string &a) {
        std::string out; reverser(a, out); return out;
    });
    m.def("deconvert_pair", &deconvert_pair);
    m.def("base_convert", [](long long b, int base) {
        std::string out; base_convert(b, out, base); return out;
    });
    m.def("base_deconvert", [](const std::string &a, int base) {
        long long b; base_deconvert(a, b, base); return b;
    });
    m.def("custom_rot", [](const std::string &a, int add) {
        std::string out; custom_rot(a, add, out); return out;
    }, py::arg("text"), py::arg("shift"));
    m.def("rot13", [](const std::string &a) {
        std::string out; rot13(a, out); return out;
    });
    m.def("a1z26", [](const std::string &a, char sep) {
        std::string out; a1z26(a, out, sep); return out;
    }, py::arg("text"), py::arg("sep") = '-');
    m.def("keyboard_shift", [](const std::string &a, int n, bool encrypt) {
        std::string out; keyboard_shift(a, out, n, encrypt); return out;
    }, py::arg("text"), py::arg("rows"), py::arg("encrypt") = true);

    // ── historical_ciphers ──

    m.def("atbash", [](const std::string &a) {
        std::string out; atbash(a, out); return out;
    });
    m.def("caesar", [](const std::string &a) {
        std::string out; caesar(a, out); return out;
    });
    m.def("vigenere", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; vigenere(a, key, out, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("autokey", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; autokey(a, key, out, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("beaufort", [](const std::string &a, const std::string &key) {
        std::string out; beaufort(a, key, out); return out;
    });
    m.def("railfence", [](const std::string &a, int key, int offset) {
        std::string out; railfence(a, out, key, offset); return out;
    }, py::arg("text"), py::arg("key"), py::arg("offset") = 0);
    m.def("scytale_encrypt", [](const std::string &a, int m) {
        std::string out; scytale_encrypt(a, out, m); return out;
    });
    m.def("scytale_decrypt", [](const std::string &a, int m) {
        std::string out; scytale_decrypt(a, out, m); return out;
    });
    m.def("polybius_encrypt", [](const std::string &alphabet, const std::string &a) {
        std::string out; polybius_encrypt(alphabet, a, out); return out;
    }, py::arg("alphabet"), py::arg("text"));
    m.def("polybius_decrypt", [](const std::string &alphabet, const std::string &a) {
        std::string out; polybius_decrypt(alphabet, a, out); return out;
    }, py::arg("alphabet"), py::arg("text"));
    m.def("columnar_encrypt", [](const std::string &a, const std::string &key) {
        std::string out; columnar_encrypt(a, out, key); return out;
    });
    m.def("columnar_decrypt", [](const std::string &a, const std::string &key, int original_len) {
        std::string out; columnar_decrypt(a, out, key, original_len); return out;
    }, py::arg("text"), py::arg("key"), py::arg("original_len"));
    m.def("playfair", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; playfair(a, out, key, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);

    m.def("bifid_encrypt", [](const std::string &msg, py::list rows) {
        if (py::len(rows) != 5)
            throw std::runtime_error("bifid needs exactly 5 rows of 6 chars");
        std::string r[5];
        for (int i = 0; i < 5; i++) r[i] = rows[i].cast<std::string>();
        char grid[6][6]; int row_of[256], col_of[256];
        build_bifid_grid(r, grid, row_of, col_of);
        std::string out; bifid_encrypt(msg, out, grid, row_of, col_of); return out;
    });
    m.def("bifid_decrypt", [](const std::string &msg, py::list rows) {
        if (py::len(rows) != 5)
            throw std::runtime_error("bifid needs exactly 5 rows of 6 chars");
        std::string r[5];
        for (int i = 0; i < 5; i++) r[i] = rows[i].cast<std::string>();
        char grid[6][6]; int row_of[256], col_of[256];
        build_bifid_grid(r, grid, row_of, col_of);
        std::string out; bifid_decrypt(msg, out, grid, row_of, col_of); return out;
    });
    m.def("build_bifid_grid", [](py::list rows) {
        if (py::len(rows) != 5)
            throw std::runtime_error("bifid needs exactly 5 rows of 6 chars");
        std::string r[5];
        for (int i = 0; i < 5; i++) r[i] = rows[i].cast<std::string>();
        char grid[6][6]; int row_of[256], col_of[256];
        build_bifid_grid(r, grid, row_of, col_of);
        py::list out;
        for (int i = 0; i < 6; i++) out.append(py::str(grid[i], 6));
        return out;
    });

    m.def("trifid", [](const std::string &a, const std::string &key, int period, bool encrypt) {
        std::string out; trifid(a, out, key, period, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("period"), py::arg("encrypt") = true);
    m.def("four_square", [](const std::string &a, const std::string &key1, const std::string &key2, bool encrypt) {
        std::string out; four_square(a, out, key1, key2, encrypt); return out;
    }, py::arg("text"), py::arg("key1"), py::arg("key2"), py::arg("encrypt") = true);
    m.def("adfgvx", [](const std::string &a, const std::string &polybius_key, const std::string &col_key, bool encrypt) {
        std::string out; adfgvx(a, out, polybius_key, col_key, encrypt); return out;
    }, py::arg("text"), py::arg("polybius_key"), py::arg("col_key"), py::arg("encrypt") = true);
    m.def("bacon", [](const std::string &a, bool encrypt) {
        std::string out; bacon(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);

    m.def("morse_encode", [](const std::string &a) {
        std::string out; morse_encode(a, out); return out;
    });
    m.def("morse_decode", [](const std::string &a) {
        std::string out; morse_decode(a, out); return out;
    });

    m.def("braille_to_dots", [](const std::string &cell) {
        std::string out; braille_to_dots(cell, out); return out;
    });
    m.def("braille_print_dots", &braille_print_dots);
    m.def("simple_dots_to_braille", [](const std::string &dots) {
        std::string out; simple_dots_to_braille(dots, out); return out;
    });
    m.def("braille_to_simple_dots", [](const std::string &cell) {
        std::string out; braille_to_simple_dots(cell, out); return out;
    });
    m.def("braille_encode", [](const std::string &a) {
        std::string out; braille_encode(a, out); return out;
    });
    m.def("braille_decode", [](const std::string &a) {
        std::string out; braille_decode(a, out); return out;
    });

    // ── essential_ciphers ──

    m.def("raw_bytes_print", &raw_bytes_print);
    m.def("large_encrypt", [](const std::string &a, int base) {
        std::string out; large_encrypt(a, out, base); return out;
    }, py::arg("text"), py::arg("base") = 36);
    m.def("large_decrypt", [](const std::string &a, int base) {
        std::string out; large_decrypt(a, out, base); return out;
    }, py::arg("text"), py::arg("base") = 36);
    m.def("hex_xor", [](const std::string &a, unsigned char key) {
        std::string out; hex_xor(a, key, out); return out;
    });
    m.def("str_xor", [](const std::string &a, const std::string &b) {
        std::string out; str_xor(a, b, out); return py::bytes(out);
    });
    m.def("urlcode", [](const std::string &a, bool encrypt) {
        std::string out; urlcode(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);
    m.def("codepoint_to_utf8", [](unsigned int cp) {
        std::string out; codepoint_to_utf8(cp, out); return out;
    });
    m.def("utf8_to_codepoint", [](const std::string &a, int i) {
        int pos = i;
        unsigned int cp = utf8_to_codepoint(a, pos);
        return py::make_tuple(cp, pos);
    });
    m.def("rot8000_cp", &rot8000_cp);
    m.def("rot8000", [](const std::string &a, int key, bool encrypt) {
        std::string out; rot8000(a, out, key, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("octal", [](const std::string &a, bool encrypt) {
        std::string out; octal(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);
    m.def("binary", [](const std::string &a, bool encrypt) {
        std::string out; binary(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);

    // ── bytes ──

    m.def("little_endian_encode", [](long long val, int bytes) {
        std::string out; little_endian_encode(val, out, bytes); return out;
    }, py::arg("val"), py::arg("bytes") = 8);
    m.def("big_endian_encode", [](long long val, int bytes) {
        std::string out; big_endian_encode(val, out, bytes); return out;
    }, py::arg("val"), py::arg("bytes") = 8);
    m.def("little_endian_decode", [](const std::string &a) {
        long long out; little_endian_decode(a, out); return out;
    });
    m.def("big_endian_decode", [](const std::string &a) {
        long long out; big_endian_decode(a, out); return out;
    });
    m.def("proper_base_convert", [](const std::string &input, int bits_per_char, const std::string &alphabet) {
        std::string out; proper_base_convert(input, out, bits_per_char, alphabet); return out;
    }, py::arg("input"), py::arg("bits_per_char"), py::arg("alphabet"));

    // ── standard_ciphers ──

    m.def("rot47", [](const std::string &a) {
        std::string out; rot47(a, out); return out;
    });
    m.def("keyword_cipher", [](const std::string &a, const std::string &keyword, bool encrypt) {
        std::string out; keyword_cipher(a, out, keyword, encrypt); return out;
    }, py::arg("text"), py::arg("keyword"), py::arg("encrypt") = true);
    m.def("substitution_encrypt", [](const std::string &a, const std::string &key) {
        std::string out; substitution_encrypt(a, out, key); return out;
    });
    m.def("substitution_decrypt", [](const std::string &a, const std::string &key) {
        std::string out; substitution_decrypt(a, out, key); return out;
    });
    m.def("frequency_analysis", [](const std::string &a) {
        std::vector<std::pair<char, double>> freqs;
        frequency_analysis(a, freqs);
        py::list result;
        for (auto &f : freqs) result.append(py::make_tuple(f.first, f.second));
        return result;
    });
    m.def("substitution_solve", [](const std::string &a) {
        std::string out, mapping;
        substitution_solve(a, out, mapping);
        return py::make_tuple(out, mapping);
    });
    m.def("index_of_coincidence", &index_of_coincidence);
    m.def("find_key_lengths", [](const std::string &a, int max_len) {
        std::vector<int> lengths;
        find_key_lengths(a, lengths, max_len);
        return lengths;
    }, py::arg("text"), py::arg("max_len") = 20);
    // ── outdated_ciphers ──

    m.def("rc4", [](const std::string &input, const std::string &key) {
        std::string out; rc4(input, out, key); return py::bytes(out);
    });
    m.def("des_ecb", [](const std::string &input, const std::string &key, bool encrypt) {
        std::string out; des_ecb(input, out, key, encrypt); return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("encrypt") = true);
    m.def("des3_ecb", [](const std::string &input, const std::string &key, bool encrypt) {
        std::string out; des3_ecb(input, out, key, encrypt); return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("encrypt") = true);
    m.def("blowfish_ecb", [](const std::string &input, const std::string &key, bool encrypt) {
        std::string out; blowfish_ecb(input, out, key, encrypt); return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("encrypt") = true);
    m.def("vigenere_autokey_broken", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; vigenere_autokey_broken(a, key, out, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("enigma", [](const std::string &input, const std::vector<int> &rotors, const std::vector<int> &offsets, const std::vector<std::pair<int,int>> &plugboard) {
        std::string out; enigma(input, out, rotors, offsets, plugboard); return out;
    });

    // ── bruteforce_ciphers ──

    m.def("brute_rotate", [](const std::string &a) {
        std::string s = a; brute_rotate(s); return s;
    });
    m.def("brute_rot_all", &brute_rot_all);
    m.def("brute_caesar_all", &brute_caesar_all);
    m.def("brute_railfence_all", &brute_railfence_all);
    m.def("brute_xor_single_byte", [](const std::string &a) {
        auto vec = brute_xor_single_byte(a);
        py::list result;
        for (auto &s : vec) result.append(py::bytes(s));
        return result;
    });
    m.def("brute_vigenere_keylength", &brute_vigenere_keylength);

    // module-level constants
    m.attr("padding") = py::str(std::string(1, padding));
}
