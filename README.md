# Obscuron Cryptographic Suite
 
A desktop cryptographic toolkit built in C++ with Qt, inspired by CyberChef.
Supports a wide range of classical and encoding ciphers with a clean dark UI.
Still in alpha, V0.3
 
---
 
## Features
 
- A1Z26, Morse, Braille encode/decode
- Vigenere, Atbash, Beaufort, Caesar, ROT/custom rotation
- Rail Fence, Columnar transposition
- Hex XOR, Binary, Octal, URL encoding
- ROT8000 (Unicode-aware rotation)
- Large base conversion (base 2–62)
- Little/Big endian encoding
---
 
## Built With
 
- C++17
- Qt 6 (Widgets)
---
 
## Project Structure
 
```
Obscuron-Crypto-Suite/
├── main.cpp           # entry point, launches MenuWindow
├── menuwindow.h/.cpp  # main menu screen
├── mainwindow.h/.cpp  # cipher workspace
├── basic.h/.cpp       # all cipher and encoding logic
├── includes.h         # shared Qt and std includes
└── Obscuron-Crypto-Suite.pro
```
 
---
 
## Building
 
1. Install Qt 6 and Qt Creator
2. Open `Obscuron-Crypto-Suite.pro` in Qt Creator
3. Run qmake → Build
Or from the command line:
```bash
qmake Obscuron-Crypto-Suite.pro
make
```
 
---
 
## Color Palette
 
| Role | Hex | RGB |
|---|---|---|
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
