"""Obscuron Crypto Suite — C++ accelerated cipher library.

Provides Python bindings to all cipher and encoding functions.
"""

from _obscuron_core import *

__all__ = [
    # basic_ciphers
    "split", "parser", "reverser", "deconvert_pair",
    "base_convert", "base_deconvert",
    "custom_rot", "rot13", "a1z26", "keyboard_shift",
    # historical_ciphers
    "atbash", "caesar",
    "vigenere", "autokey", "beaufort",
    "railfence", "scytale_encrypt", "scytale_decrypt",
    "polybius_encrypt", "polybius_decrypt",
    "columnar_encrypt", "columnar_decrypt",
    "playfair", "bifid_encrypt", "bifid_decrypt", "build_bifid_grid",
    "trifid", "four_square", "adfgvx", "bacon",
    "morse_encode", "morse_decode",
    "braille_to_dots", "braille_print_dots",
    "simple_dots_to_braille", "braille_to_simple_dots",
    "braille_encode", "braille_decode",
    # essential_ciphers
    "raw_bytes_print",
    "large_encrypt", "large_decrypt",
    "hex_xor", "str_xor", "urlcode",
    "codepoint_to_utf8", "utf8_to_codepoint",
    "rot8000_cp", "rot8000",
    "octal", "binary",
    # bytes
    "little_endian_encode", "big_endian_encode",
    "little_endian_decode", "big_endian_decode",
    "proper_base_convert",
    # standard_ciphers
    "rot47", "keyword_cipher",
    "substitution_encrypt", "substitution_decrypt",
    "frequency_analysis", "substitution_solve",
    "index_of_coincidence", "find_key_lengths",
    # outdated_ciphers
    "rc4", "des_ecb", "des3_ecb",
    "blowfish_ecb", "vigenere_autokey_broken", "enigma",
    # bruteforce_ciphers
    "brute_rotate", "brute_rot_all",
    "brute_caesar_all", "brute_railfence_all",
    "brute_xor_single_byte", "brute_vigenere_keylength",
]
