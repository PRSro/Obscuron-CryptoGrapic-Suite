# Obscuron Cryptographic Suite

A desktop cryptographic toolkit built in C++ with Qt, inspired by CyberChef.
Also includes a **standalone CLI** (`ob-crypt`) with 80+ cipher operations,
RSA attacks, elliptic curve arithmetic, DLP solvers, and lattice reduction.

Still in alpha, V0.3

---

## Features

### CLI (`ob-crypt`)
- Classical ciphers: Caesar, Vigenere, Playfair, Enigma, ADFGVX, Rail Fence
- Modern ciphers: AES-ECB/CBC/CTR, ChaCha20, Blowfish, DES/3DES, RC4
- Encoding: Hex, Base64, Base32, Binary, Octal, URL, Braille, Morse
- Hash: MD5, SHA-1, SHA-256, SHA-512, BLAKE2b, BLAKE2s, HMAC
- Key derivation: PBKDF2, Argon2id
- JWT sign/parse, QR code generation, LSB steganography
- Brute force: Caesar (multi-threaded), ROT, Rail Fence, XOR, Vigenere
- **RSA**: Decrypt, Wiener attack, Hastad broadcast, Common-modulus attack,
  Fermat/Pollard factorization, Parity oracle, Encode, Key info analysis
- **Elliptic curves**: Point addition, scalar multiplication
- **Discrete log**: Baby-step giant-step, Pohlig-Hellman
- **Lattice reduction**: LLL algorithm
- Auto-detection and statistical analysis (entropy, IoC, frequency)
- Chain multiple operations in a pipeline

### GUI (Qt)
- A1Z26, Morse, Braille encode/decode
- Vigenere, Atbash, Beaufort, Caesar, ROT/custom rotation
- Rail Fence, Columnar transposition
- Hex XOR, Binary, Octal, URL encoding
- ROT8000 (Unicode-aware rotation)
- Large base conversion (base 2–62)
- Little/Big endian encoding

---

## CLI Usage

```
ob-crypt <cipher> [options] [input]
ob-crypt --list              # List all available ciphers
ob-crypt detect [--top N] input   # Auto-detect cipher type
ob-crypt analyze input       # Statistical analysis
ob-crypt chain --steps s1,s2 input  # Multi-step pipeline
```

### Global Options
| Flag | Description |
|------|-------------|
| `--raw` | Machine-readable output (no labels) |
| `--hex-input` | Decode input from hex before processing |
| `--hex-output` | Encode output as hex |
| `-f file` | Read input from file |
| `-i iv/nonce` | IV or nonce (hex) |
| `-k key` | Key for cipher operations |

### RSA Examples
```bash
# Wiener attack (small d)
ob-crypt rsa-wiener -e <e> -n <n> -c <c>

# Key analysis
ob-crypt rsa-info -n <n> -e <e>

# Fermat factorization
ob-crypt rsa-factor-fermat -n <n>

# Pollard Rho factorization
ob-crypt rsa-factor-pollard -n <n>

# Common modulus attack
ob-crypt rsa-common-modulus -n <n> -e1 <e1> -e2 <e2> -c1 <c1> -c2 <c2>

# Parity oracle
ob-crypt rsa-parity-oracle -n <n> -e <e> -c <c> --oracle "./parity.sh"
```

### Brute Force Examples
```bash
ob-crypt brute-rotate "khoor"       # All 26 ROT shifts (0-25)
ob-crypt brute-caesar "khoor"       # Caesar 1-25 (multi-threaded)
ob-crypt brute-railfence --max 15 "ciphertext"
ob-crypt brute-xor --hex-input "1b2c3d"
ob-crypt brute-vigenere --max 12 "ciphertext"
```

### Chain Pipeline
```bash
# Base64 decode then hex decode
ob-crypt chain --steps "base64,hex" "SGVsbG8="
# Base64 decode then auto-detect
ob-crypt chain --steps "base64" --detect "SGVsbG8="
```

---

## Built With

- C++17
- Qt 6 (Widgets) — GUI only
- NTL (Number Theory Library) — RSA, EC, DLP, LLL

---

## CLI Project Structure

```
CLI/
├── ob-crypt              # compiled binary
├── ob-crypt.1            # man page
├── Makefile
├── main.cpp              # entry point
├── includes/
│   ├── basic_ciphers.h / historical_ciphers.h / essential_ciphers.h
│   ├── standard_ciphers.h / modern_ciphers.h / outdated_ciphers.h
│   ├── bruteforce_ciphers.h / detector.h
│   ├── bytes.h / bigint.hpp / mathutils.hpp
│   ├── ntl_bridge.h      # NTL-based RSA/EC/DLP/LLL interface
│   ├── register_handlers.h / context.h / thread_pool.h
│   └── branch_explorer.h
└── src/
    ├── *.cpp              # cipher implementations
    ├── register_*.cpp     # CLI handler registrations
    ├── ntl_bridge.cpp     # NTL wrappers (RSA decrypt, Wiener, etc.)
    └── bigint.cpp         # big integer class
```

---

## Building

### CLI Only (no Qt required)
```bash
cd CLI
make -j4
./ob-crypt --list
```

### GUI (requires Qt 6)
```bash
qmake Obscuron-Crypto-Suite.pro
make
```

> Note: NTL must be installed for RSA, EC, DLP, and LLL commands.
> Install on Debian/Ubuntu: `apt install libntl-dev`
> Install on Arch: `pacman -S ntl`
> Or build from source: https://libntl.org

---

## Color Palette

| Role | Hex | RGB |
|------|-----|-----|
| Background | `#080810` | 8, 8, 16 |
| Surface | `#0e0e1a` | 14, 14, 26 |
| Surface 2 | `#141428` | 20, 20, 40 |
| Border | `#1e1e3a` | 30, 30, 58 |
| Accent | `#7b5ea7` | 123, 94, 167 |
| Accent glow | `#c4b0ff` | 196, 176, 255 |
| Text | `#e8e6f0` | 232, 230, 240 |
| Output | `#7dd3c0` | 125, 211, 192 |

---

## License

MIT
