# Obscuron Crypto Suite

A comprehensive cryptographic toolkit implemented in C++17, offering both a **command-line interface** (`ob-crypt`) and a **graphical desktop application** (Qt6 Widgets). Supports classical ciphers, modern cryptography, encoding schemes, brute-force tools, and a cipher detector — inspired by CyberChef.

> **Status:** Alpha (v0.3)

---

## Architecture

The project produces **two separate binaries** that share a common cipher library:

```
Obscuron-Crypto-Suite/
├── CLI/                         # Command-line binary (ob-crypt)
│   ├── main.cpp                 # CLI entry point & argument dispatch
│   ├── Makefile                 # Standalone Makefile (no Qt required)
│   ├── includes/                # Shared header files
│   └── src/                     # Shared cipher implementations
│
├── GUI/                         # Desktop binary (Obscuron-Crypto-Suite)
│   ├── main.cpp                 # Qt application entry point
│   ├── mainwindow.h/.cpp        # Cipher workspace (drag-and-drop recipe UI)
│   ├── menuwindow.h/.cpp       # Application menu / launcher
│   ├── numberwindow.h/.cpp     # Number conversion workspace
│   ├── recipe_engine.h/.cpp    # Chained multi-step cipher pipeline
│   ├── visualizer_widgets.h/.cpp # Frequency/entropy/encoding visualizers
│   ├── theme_manager.h/.cpp    # Dark / Light / OLED theme support
│   ├── advanced_crypt_dialog.h/.cpp   # Advanced crypto parameter dialog
│   ├── advanced_number_dialog.h/.cpp  # Advanced number conversion dialog
│   ├── colours.h                # Color palette definitions
│   ├── includes.h               # Shared Qt/STL includes
│   └── Obscuron-Crypto-Suite.pro # qmake project file
│
├── .gitignore
└── README.md
```

Both binaries compile the same cipher sources from `CLI/src/` against `CLI/includes/`.

---

## Binaries

| Binary | Path | Description |
|--------|------|-------------|
| `ob-crypt` | `CLI/ob-crypt` | Command-line tool — pipe data, specify cipher & parameters |
| `Obscuron-Crypto-Suite` | `GUI/Obscuron-Crypto-Suite` | Desktop GUI — visual recipe builder with drag-and-drop |

---

## Ciphers & Operations

### Basic Ciphers
| Operation | Description |
|-----------|-------------|
| `custom_rot` | Rotate letters by arbitrary shift |
| `rot13` | ROT13 (shift by 13) |
| `a1z26` | A1Z26 encoding (A=1, B=2, ...) |
| `keyboard_shift` | Shift characters on a QWERTY keyboard layout |
| `split` | Split string into characters |
| `reverser` | Reverse a string |
| `base_convert` | Convert a number between arbitrary bases (2–62) |

### Historical / Classical Ciphers
| Operation | Description |
|-----------|-------------|
| `atbash` | Atbash substitution (reverse alphabet) |
| `affine` | Affine cipher: `E(x) = (ax + b) mod 26` |
| `caesar` | Caesar cipher (shift by key) |
| `vigenere` | Vigenere cipher with keyword |
| `autokey` | Autokey cipher (Vigenere with priming key) |
| `beaufort` | Beaufort cipher (reciprocal of Vigenere) |
| `railfence` | Rail Fence transposition (zigzag) |
| `scytale` | Scytale transposition (ancient Greek) |
| `polybius` | Polybius square encode/decode |
| `columnar` | Columnar transposition with keyword |
| `playfair` | Playfair digraph substitution (5×5 grid) |
| `bifid` | Bifid cipher (combining substitution & transposition) |
| `trifid` | Trifid cipher (3D extension of Bifid) |
| `four_square` | Four-Square cipher (digraph substitution) |
| `adfgvx` | ADFGVX cipher (Polybius + columnar transposition) |
| `bacon` | Baconian cipher (5-letter binary encoding) |
| `morse` | Morse code encode/decode |
| `braille` | Braille dot-pattern encode/decode |

### Essential / Encoding Ciphers
| Operation | Description |
|-----------|-------------|
| `large_encrypt` / `large_decrypt` | Big-integer base conversion (base 2–62) using GMP |
| `hex_xor` / `str_xor` | XOR a string against a hex key or another string |
| `urlcode` | URL percent-encoding encode/decode |
| `rot8000` | Unicode-aware rotation through BMP code points |
| `octal` | Octal encoding/decoding |
| `binary` | Binary encoding/decoding |

### Standard Ciphers & Cryptanalysis
| Operation | Description |
|-----------|-------------|
| `rot47` | ROT47 (printable ASCII shift by 47) |
| `keyword_cipher` | Keyword-based monoalphabetic substitution |
| `substitution` | Arbitrary substitution cipher (encrypt/decrypt/solve) |
| `frequency_analysis` | Letter frequency distribution (A–Z) |
| `index_of_coincidence` | Compute IoC for polyalphabetic detection |
| `find_key_lengths` | Kasiski examination — find probable key lengths |

### Outdated / Weak Ciphers
| Operation | Description |
|-----------|-------------|
| `rc4` | RC4 stream cipher |
| `des_ecb` | DES in ECB mode (56-bit key) |
| `des3_ecb` | Triple-DES in ECB mode |
| `blowfish_ecb` | Blowfish in ECB mode |
| `enigma` | Enigma machine simulation (configurable rotors, offsets, plugboard) |

### Modern Ciphers & Cryptography
| Operation | Description |
|-----------|-------------|
| **Hashes** | |
| `md5_hash` | MD5 (128-bit digest) |
| `sha1_hash` | SHA-1 (160-bit digest) |
| `sha256_hash` | SHA-256 (256-bit digest) |
| `sha512_hash` | SHA-512 (512-bit digest) |
| `blake2b_hash` | BLAKE2b (keyed or unkeyed, up to 512-bit) |
| `blake2s_hash` | BLAKE2s (keyed or unkeyed, up to 256-bit) |
| **MAC / KDF** | |
| `hmac_sha256` / `hmac_sha512` | HMAC with SHA-256 / SHA-512 |
| `pbkdf2_sha256` | PBKDF2 key derivation (configurable iterations & output length) |
| `argon2id_hash` | Argon2id memory-hard KDF |
| **Symmetric** | |
| `aes_encrypt` / `aes_decrypt` | AES (ECB / CBC / CTR modes, 128/192/256-bit keys) |
| `chacha20_crypt` | ChaCha20 stream cipher |
| `poly1305_mac` | Poly1305 one-time authenticator |
| **Other** | |
| `base64` / `base64url` | Base64 and Base64URL encode/decode |
| `jwt_parse` / `jwt_sign` | JSON Web Token parsing and signing |
| `generate_qr_matrix` | QR code matrix generation |
| `lsb_embed` / `lsb_extract` | LSB steganography (embed/extract text in carrier data) |

### Brute-Force Tools
| Operation | Description |
|-----------|-------------|
| `brute_rot_all` | Try all 26 ROT/shift variations |
| `brute_caesar_all` | Try all 25 Caesar shifts |
| `brute_railfence_all` | Brute-force Rail Fence with key up to N |
| `brute_xor_single_byte` | Try all 256 single-byte XOR keys |
| `brute_vigenere_keylength` | Brute-force Vigenere key up to given length |

### Detection & Analysis
| Operation | Description |
|-----------|-------------|
| `detect` | Automatic cipher detection (top-N candidates with confidence) |
| `analyze` | Statistical analysis (encoding, length, IoC, entropy, byte distribution, letter frequencies) |
| `chain` | Multi-step cipher pipeline (sequential encode/decode with optional detection) |

### Byte Utilities
| Operation | Description |
|-----------|-------------|
| `little_endian_encode` / `big_endian_encode` | Encode integer to N-byte endian representation |
| `little_endian_decode` / `big_endian_decode` | Decode endian bytes to integer |
| `proper_base_convert` | Chunk-oriented base encoding (preserves leading zeros) |

---

## CLI Usage

```
Usage: ob-crypt [options] <cipher> [input] [parameters]

Global options:
  --raw                     Machine-readable output (no labels)
  --hex-input               Decode input from hex before processing
  --hex-output              Encode output as hex
  -f <file>                 Read input from file
  -                         Read input from stdin

Modes:
  ob-crypt [--list]         List all available ciphers
  ob-crypt [--help|-h]      Show help / usage suggestions
  ob-crypt detect [--top N] <input>     Detect cipher (top N candidates)
  ob-crypt analyze <input>              Statistical analysis of input
  ob-crypt chain --steps <steps> <input>  Multi-step pipeline

Cipher parameters:
  -s <int>    Shift (Caesar, ROT)
  -k <str>    Key string (Vigenere, Playfair, Columnar, RC4, XOR, ...)
  -a <int>    Affine multiplier (a)
  -b <int>    Affine offset (b)
  -r <str>    Enigma rotors (comma-separated)
  -o <str>    Enigma offsets (comma-separated)
  -p <str>    Enigma plugboard (pairs, e.g. "0:1,2:3")
  --decrypt   Decryption mode (where supported)
  --len <int> Original plaintext length (for columnar decrypt)
  --offset <int> Offset (Rail Fence)
```

### CLI Examples

```bash
# Encrypt with Caesar (shift 7)
echo "hello world" | ./ob-crypt caesar -s 7

# Decrypt with Vigenere
./ob-crypt vigenere -k secret --decrypt "olssv dvysk"

# Encode to base64
./ob-crypt large_encrypt -b 64 "hello"

# Automatic cipher detection
./ob-crypt detect "uryyb jbeyq"

# Analyze ciphertext
./ob-crypt analyze -f ciphertext.bin

# Multi-step chain: base64 decode, then hex decode
./ob-crypt chain --steps "base64,hex" "SGVsbG8="

# Enigma simulation
./ob-crypt enigma -r "1,2,3" -o "0,0,0" -p "0:1,2:3" "HELLO"

# Brute-force single-byte XOR
./ob-crypt brute_xor

# AES encryption (via GUI binary or imported in chain)
# See --list for all available ciphers
./ob-crypt --list
```

### Input Sources

1. **Inline argument:** `./ob-crypt caesar "hello"`
2. **File:** `./ob-crypt caesar -f input.txt`
3. **Stdin:** `echo "hello" | ./ob-crypt caesar -` or `./ob-crypt caesar` (reads stdin if not a TTY)
4. **Hex input:** `./ob-crypt --hex-input caesar "68656c6c6f"`

---

## GUI Usage

The GUI provides a visual drag-and-drop recipe builder similar to CyberChef.

### Features

- **Menu Window**: Launcher with quick-access buttons for each cipher category
- **Cipher Workspace** (`MainWindow`): Input/output panels with a recipe chain
- **Recipe Engine** (`RecipeEngine`): Chain multiple operations sequentially; reorder, enable/disable steps; import/export as JSON or macro scripts
- **Visualizer Widgets**:
  - **Frequency Histogram**: Letter frequency vs. standard English (hover for values)
  - **Entropy Heatmap**: Per-block byte randomness visualization
  - **Shannon Entropy Graph**: Rolling entropy over a sliding window
  - **Encoding Wheel**: Interactive radix conversion view (binary, octal, decimal, hex, base64)
- **Advanced Dialogs**: Configure AES/ChaCha20/AES-GCM parameters, key derivation, HMAC, etc.
- **Themes**: Dark (default), Light, and OLED modes via `ThemeManager`

### Running

```bash
cd GUI
./Obscuron-Crypto-Suite
```

Or open `GUI/Obscuron-Crypto-Suite.pro` in Qt Creator and run from there (select the Qt 6 kit).

---

## Building

### Prerequisites

| Dependency | CLI | GUI |
|------------|-----|-----|
| C++17 compiler (g++ ≥ 8 / clang ≥ 7) | Required | Required |
| NTL (Number Theory Library) | Optional | Required |
| Qt 6 (Widgets module) | — | Required |

Install on Debian/Ubuntu:
```bash
sudo apt install build-essential libntl-dev qt6-base-dev
```

Install on Arch:
```bash
sudo pacman -S base-devel ntl qt6-base
```

### Build the CLI

```bash
cd CLI
make
```

Produces `CLI/ob-crypt`.

### Build the GUI

```bash
cd GUI
qmake6 Obscuron-Crypto-Suite.pro
make
```

Produces `GUI/Obscuron-Crypto-Suite`.

Or open `GUI/Obscuron-Crypto-Suite.pro` in Qt Creator, then Build.

---

## Dependencies

- **NTL** (GUI only) — number theory library; used in advanced number/cryptography dialogs
- **Qt 6 Widgets** (GUI only) — application windowing, event loop, and UI components

---

## Color Palette

| Role | Hex | RGB |
|------|-----|-----|
| Background | `#0a0514` | 10, 5, 20 |
| Surface | `#120a20` | 18, 10, 32 |
| Surface 2 | `#1a1030` | 26, 16, 48 |
| Border | `#1e1850` | 30, 24, 80 |
| Border (hi) | `#2a2270` | 42, 34, 112 |
| Accent | `#4a7cff` | 74, 124, 255 |
| Accent (hi) | `#6b9cff` | 107, 156, 255 |
| Accent glow | `#00d4a0` | 0, 212, 160 |
| Text | `#e0e0f0` | 224, 224, 240 |
| Text (dim) | `#8880a0` | 136, 128, 160 |
| Text (dead) | `#3a3060` | 58, 48, 96 |
| Action | `#006644` | 0, 102, 68 |
| Action (hi) | `#00aa77` | 0, 170, 119 |
| Output | `#00cc88` | 0, 204, 136 |

---

## License

MIT
