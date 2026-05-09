#include "basic.h"

const char padding='0';
const std::string alphabet="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-;<=>?@^_`{|}~[].,";
const std::string alphabet_to_morse="abcdefghijklmnopqrstuvwxyz0123456789 ";
const std::string morse_to_alphabet[38] = {
    ".-",    // a
    "-...",  // b
    "-.-.",  // c
    "-..",   // d
    ".",     // e
    "..-.",  // f
    "--.",   // g
    "....",  // h
    "..",    // i
    ".---",  // j
    "-.-",   // k
    ".-..",  // l
    "--",    // m
    "-.",    // n
    "---",   // o
    ".--.",  // p
    "--.-",  // q
    ".-.",   // r
    "...",   // s
    "-",     // t
    "..-",   // u
    "...-",  // v
    ".--",   // w
    "-..-",  // x
    "-.--",  // y
    "--..",  // z
    "-----", // 0
    ".----", // 1
    "..---", // 2
    "...--", // 3
    "....-", // 4
    ".....", // 5
    "-....", // 6
    "--...", // 7
    "---..", // 8
    "----.", // 9
    "/",     // space
    ""       // sentinel
};
const std::string braille_alphabet = "abcdefghijklmnopqrstuvwxyz ";
const std::string braille_map[28] = {
    "100000", // a
    "110000", // b
    "100100", // c
    "100110", // d
    "100010", // e
    "110100", // f
    "110110", // g
    "110010", // h
    "010100", // i
    "010110", // j
    "101000", // k
    "111000", // l
    "101100", // m
    "101110", // n
    "101010", // o
    "111100", // p
    "111110", // q
    "111010", // r
    "011100", // s
    "011110", // t
    "101001", // u
    "111001", // v
    "010111", // w
    "101101", // x
    "101111", // y
    "101011", // z
    "000000", // space
    ""        // sentinel
};

// digits reuse a-j patterns
const std::string digit_map[10] = {
    "010110", // 0 → j pattern
    "100000", // 1 → a pattern
    "110000", // 2 → b pattern
    "100100", // 3 → c pattern
    "100110", // 4 → d pattern
    "100010", // 5 → e pattern
    "110100", // 6 → f pattern
    "110110", // 7 → g pattern
    "110010", // 8 → h pattern
    "010100", // 9 → i pattern
};

const std::string NUMBER_INDICATOR = "010111"; // signals next cells are digits
const std::string LETTER_INDICATOR = "000001"; // signals back to letters


void split(const std::string &a, std::string &c) {
    std::string seq;
    int s=a.length();
    c="";
    if (s%2==1) {
        seq= {padding, a.at(0)};
        c+=seq+' ';
        for(int i=1; i<s; i+=2) {
            seq= {a.at(i), a.at(i+1)};
            c+=seq+' ';
        }
    }
    else {
        for(int i=0; i<s; i+=2) {
            seq= {a.at(i), a.at(i+1)};
            c+=seq+' ';
        }
    }
}

void parser(const std::string &a, std::string &out) {
    out="";
    for(char l:a) {
        if (l==' ') {
            continue;
        }
        else out+=l;
    }
}

void reverser(const std::string &a, std::string &c) {
    c="";
    int n=a.length();
    std::string seq;
    for (int y=n-1; y>=0; y--) {
        seq=a.at(y);
        c+=seq;
    }
}

int deconvert_pair(const std::string &pair, int base) {
    size_t h = alphabet.find(pair.at(0));
    size_t l  = alphabet.find(pair.at(1));
    if (h == std::string::npos || l == std::string::npos) {
        std::cerr << "Error: character not in alphabet\n";
        return -1;
    }
    return h * base + l;
}
void base_deconvert(const std::string &a, long long &b, int base) {
    if(a=="0") {
        b=0;
        return;
    }
    bool negative = (a.at(0) == '-');
    std::string temp=negative?a.substr(1):a, clean, c;
    split(temp,c);
    parser(c, clean);
    b=0;
    int la=clean.length();
    for(int i=0; i<la; i+=2) {
        std::string pair= {clean.at(i), clean.at(i+1)};
        b=b*(base*base)+deconvert_pair(pair, base);
    }
    if(negative)b*=-1;
}

void base_convert(long long b, std::string &final, int base) {
    final="";
    if (b==0) {
        final="0";
        return;
    }
    long long d=std::abs(b);
    while(d!=0) {
        int r=d%base;
        final+=alphabet.at(r);
        d/=base;
    }
    std::string temp;
    reverser(final, temp);
    final=temp;
    if(b<0) final.insert(0, "-");
}

void raw_bytes_print(const std::string &a) {
    for (char c : a)
        std::cout << (int)(unsigned char)c << ' ';
}

void suggestions() {
    std::cout << "THE OBSCURON's PERSONAL HEX LIBRARY IN CPP FOR SPEED AND EFFICIENCY\n";
    std::cout << "════════════════════════════════════════════════════════════════════════════════════\n";
    std::cout << "│        function      │             intent              │        params           │\n";
    std::cout << "────────────────────────────────────────────────────────────────────────────────────\n";
    std::cout << "│ split                │ chunk string into hex pairs     │ (str, &out)             │\n";
    std::cout << "│ parser               │ strip spaces from hex string    │ (str, &out)             │\n";
    std::cout << "│ reverser             │ reverse a string                │ (str, &out)             |\n";
    std::cout << "│ deconvert_pair       │ pair→value in any base          │ (str, base) → int       │\n";
    std::cout << "│ base_convert         │ number → string in base 2–62    │ (long long, &out, base) │\n";
    std::cout << "│ base_deconvert       │ string in base 2–62 → number    │ (str, &out, base)       │\n";
    std::cout << "│ raw_bytes_print      │ print raw byte values           │ (str)                   │\n";
    std::cout << "│ load_ciphertext      │ load+normalize input            │ (&out)                  │\n";
    std::cout << "│ print_ciphertext     │ display in spaced pairs         │ (str)                   │\n";
    std::cout << "│ hex_xor              │ XOR string against byte key     │ (str, key, &out)        │\n";
    std::cout << "│ large_encrypt        │ encrypt string, base 2–62       │ (str, &out, base)       │\n";
    std::cout << "│ large_decrypt        │ decrypt string, base 2–62       │ (str, &out, base)       │\n";
    std::cout << "│ hex_operators        │ command dispatcher              │ (char)                  │\n";
    std::cout << "│ suggestions          │ print this help table           │ none                    │\n";
    std::cout << "────────────────────────────────────────────────────────────────────────────────────\n";
    std::cout << "│ supported bases: 2 (bin)  8 (oct)  10 (dec)  16 (hex)  36 (alphanum lower)       │\n";
    std::cout << "│                  62 (full alphanumeric: 0-9, a-z, A-Z)                           │\n";
    std::cout << "│ alphabet: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ         │\n";
    std::cout << "════════════════════════════════════════════════════════════════════════════════════\n";
}

void large_encrypt(const std::string &a, std::string &out, int base) {
    out="";
    std::string temp=a;
    for (char ch : temp) {
        std::string part;
        base_convert((long long)(unsigned char)ch, part, base);
        out += part + ' ';
    }
}

void large_decrypt(const std::string &a, std::string &out, int base) {
    out = "";
    std::string token;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            long long val;
            base_deconvert(token, val, base);
            out += (char)(unsigned char)val;
            token = "";
        } else {
            token += c;
        }
    }
}

void hex_xor(const std::string &a, unsigned char key, std::string &out) {
    out="";
    std::string clean;
    if (a.find(' ') != std::string::npos) {
        parser(a, clean);
    } else {
        std::string paired;
        split(a, paired);
        parser(paired, clean);
    }
    int m=clean.length();
    for (int i = 0; i < m; i += 2) {
        std::string pair = { clean.at(i), clean.at(i+1) };
        unsigned char byte = (unsigned char)deconvert_pair(pair, 16);
        byte ^= key;
        std::string part;
        base_convert((long long)byte, part, 16);
        if (part.length() == 1) part = "0" + part;
        out += part + ' ';
    }
}

void custom_rot(std::string &a, int add, std::string &out){
    out="";
    for (char c:a) {
        if (c>='a' && c<='z') {
            out+= (char)(((c-'a')+add)%26+'a');
        } else if (c>='A' && c<='Z') {
            out += (char)(((c-'A')+add)%26+'A');
        } else {
            out += c;
        }
    }
}

void atbash(std::string &a, std::string &out){
    out="";
    for (char c:a) {
        if (c>='a' && c<='z') {
            out+=(char)('z'-(c-'a'));
        } else if (c>='A' && c<='Z') {
            out+=(char)('Z'-(c-'A'));
        } else {
            out+=c;
        }
    }
}

void vigenere(const std::string &a, const std::string &key, std::string &out, bool encrypt) {
    int klen=key.length();
    int ki=0;
    int sign=encrypt?1:-1;
    out="";
    for (char c : a) {
        char k = key[ki % klen];
        int shift = (k >= 'a' && k <= 'z') ? k - 'a' : k - 'A';
        if (c >= 'a' && c <= 'z') {
            out += (char)(((c - 'a') + sign * shift + 26) % 26 + 'a');
            ki++;
        } else if (c >= 'A' && c <= 'Z') {
            out += (char)(((c - 'A') + sign * shift + 26) % 26 + 'A');
            ki++;
        } else {
            out += c;
        }
    }
}

void railfence(const std::string &a, std::string &out, int key, int offset) {
    out="";
    int n=a.length(), cyc=2*(key - 1);
    for (int r=0; r<key; r++) {
        for (int j=0; j<n; j++) {
            int p=(j+offset)%cyc;
            int rail=p<key?p:cyc-p;
            if (rail==r)
                out+=a[j];
        }
    }
}

void str_xor(const std::string &a, const std::string &b, std::string &out) {
    int n=(a.length()<b.length())?a.length():b.length();
    out="";
    for (int i = 0; i < n; i++) {
        out += (char)(a[i] ^ b[i]);
    }
}

void urlcode(const std::string &a, std::string &out, bool encrypt) {
    out="";
    if (encrypt) {
        for (unsigned char ch : a) {
            if (isalnum(ch) || ch=='-' || ch=='_' || ch=='.' || ch=='~') {
                out += ch;
            } else {
                char buf[4];
                snprintf(buf, sizeof(buf), "%%%02x", ch);
                out += buf;
            }
        }
    } else {
        int n = a.length();
        for (int i=0; i<n; i++) {
            if (a[i]=='%' && i+2<n) {
                std::string hex = {a[i+1], a[i+2]};
                long long val;
                base_deconvert(hex, val, 16);
                out += (char)val;
                i += 2;
            } else if (a[i]=='+') {
                out += ' ';
            } else {
                out += a[i];
            }
        }
    }
}

/* custom encrypt because im bored
void custom_encrypt(const std::string &a, std::string &out, int key){
    std::string b,c,d,e,f,cheie2="",lout="",part,a2="132";
    for (char ch : a) {
        part="";
        base_convert((long long)(unsigned char)ch, part, 76);
        cheie2 += part;
    }
    vigenere(a, cheie2, b, 1);
    atbash(b, c);
    std::string rot_in = b;
    for(int i=23; i<45; i++){
        std::string rot_out="";
        custom_rot(rot_in, ((i%12)&key)%26, rot_out);
        rot_in = rot_out;
    }
    d=rot_in;
    large_encrypt(c, e, 67);
    for(int i=1; i+1<(int)e.length(); i++){
        lout="";
        hex_xor(d, (unsigned char)(e[i]+e[i+1]), lout);
        f += lout;
    }
    std::string g, cheie3 = "16" + cheie2 + a2 + "basjcknaskcax";
    std::string vout, cxor;
    str_xor(c, cheie3, cxor);
    std::size_t pos = std::min(cheie3.length(), c.length());
    cxor += c.substr(pos);
    vigenere(c, "20^42rwdfa", vout, 1);
    railfence(cxor, g, key, (key^(key>>3))%7);
    part="";
    base_convert(2351562LL, part, 94);
    std::string xored, key2 = "anisjdhu8adfl0" + vout;
    std::string r_key, xx = vout+g+part;
    for(int i=0; i<(int)xx.length(); i++)
        r_key += key2[i % key2.length()];
    str_xor(xx, r_key, xored);
    std::string split_out;
    split(xored, split_out);
    std::string f_c;
    parser(f, f_c);
    if(f_c.empty()) { out = split_out; return; }
    vigenere(split_out, f_c, out, 1);
} */

void beaufort(const std::string &a, const std::string &key, std::string &out) {
    int klen=key.length(), ki=0;
    out="";
    for (char c:a) {
        if (c>='a' && c<='z') {
            int shift=key[ki%klen]-'a';
            out+=(char)((shift-(c-'a')+26)%26+'a');
            ki++;
        } else if (c>='A' && c<='Z') {
            int shift=key[ki%klen]-'A';
            out+=(char)((shift-(c-'A')+26)%26+'A');
            ki++;
        } else {
            out+=c;
        }
    }
}

//wrappers, popular in CTFs

void rot13(std::string &a, std::string &out){
    custom_rot(a, 13, out);
}

void caesar(std::string &a, std::string &out){
    custom_rot(a, 3, out);
}

void octal(const std::string &a, std::string &out, bool encrypt) {
    out = "";
    if (encrypt) {
        // encode each character to its octal value
        for (unsigned char ch : a) {
            std::string part;
            base_convert((long long)ch, part, 8);
            out += part + " ";
        }
    } else {
        // decode each octal token back to character
        std::string token;
        for (char c : a + " ") {
            if (c == ' ') {
                if (token.empty()) continue;
                long long val;
                base_deconvert(token, val, 8);
                out += (char)(unsigned char)val;
                token = "";
            } else {
                token += c;
            }
        }
    }
}

void binary(const std::string &a, std::string &out, bool encrypt) {
    out = "";
    if (encrypt) {
        for (unsigned char ch : a) {
            std::string part;
            base_convert((long long)ch, part, 2);
            // pad to 8 bits
            while ((int)part.length() < 8) part = "0" + part;
            out += part + " ";
        }
    } else {
        std::string token;
        for (char c : a + " ") {
            if (c == ' ') {
                if (token.empty()) continue;
                long long val;
                base_deconvert(token, val, 2);
                out += (char)(unsigned char)val;
                token = "";
            } else {
                token += c;
            }
        }
    }
}

void morse_encode(std::string a, std::string &out){
    out="";
    for (char c:a){
        char lower=tolower(c);
        size_t pos=alphabet_to_morse.find(lower);
        if (pos!=std::string::npos){
            out+=morse_to_alphabet[pos]+" ";
        }
    }
}

void morse_decode(std::string a, std::string &out) {
    out = "";
    std::string token;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            if (token == "/") {
                out += ' ';
            } else {
                for (int i = 0; i < 37; i++) {
                    if (morse_to_alphabet[i] == token) {
                        out += alphabet_to_morse[i];
                        break;
                    }
                }
            }
            token = "";
        } else {
            token += c;
        }
    }
}

//braile functions

void braille_to_dots(const std::string &cell, std::string &out) {
    out = "";
    if (cell.length() != 6) return;
    // top row
    out += (cell[0]=='1') ? "● " : "○ ";
    out += (cell[1]=='1') ? "●" : "○";
    out += "\n";
    // middle row
    out += (cell[2]=='1') ? "● " : "○ ";
    out += (cell[3]=='1') ? "●" : "○";
    out += "\n";
    // bottom row
    out += (cell[4]=='1') ? "● " : "○ ";
    out += (cell[5]=='1') ? "●" : "○";
    out += "\n";
}
// display entire braille string as dots
void braille_print_dots(const std::string &a) {
    std::string token;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            if (token == NUMBER_INDICATOR) {
                std::cout << "[NUM]\n";
            } else if (token == LETTER_INDICATOR) {
                std::cout << "[LET]\n";
            } else {
                std::string dots;
                braille_to_dots(token, dots);
                std::cout << dots << "\n";
            }
            token = "";
        } else {
            token += c;
        }
    }
}
// simpler: use # for raised dot, . for flat
// "## \n.. \n.. \n" = "110000" = 'a'
void simple_dots_to_braille(const std::string &dots, std::string &out) {
    out = "";
    for (char c : dots) {
        if (c == '#') out += '1';
        else if (c == '.') out += '0';
        // ignore spaces and newlines
    }
}

void braille_to_simple_dots(const std::string &cell, std::string &out) {
    out = "";
    if (cell.length() != 6) return;
    out += (cell[0]=='1') ? "# " : ". ";
    out += (cell[1]=='1') ? "#" : ".";
    out += "\n";
    out += (cell[2]=='1') ? "# " : ". ";
    out += (cell[3]=='1') ? "#" : ".";
    out += "\n";
    out += (cell[4]=='1') ? "# " : ". ";
    out += (cell[5]=='1') ? "#" : ".";
    out += "\n";
}

void braille_encode(std::string a, std::string &out) {
    out = "";
    bool in_number_mode = false;
    for (char c : a) {
        if (isdigit(c)) {
            if (!in_number_mode) {
                out += NUMBER_INDICATOR + " "; // prefix before digit sequence
                in_number_mode = true;
            }
            out += digit_map[c - '0'] + " ";
        } else {
            if (in_number_mode) {
                out += LETTER_INDICATOR + " "; // switch back to letter mode
                in_number_mode = false;
            }
            char lower = tolower(c);
            size_t pos = braille_alphabet.find(lower);
            if (pos != std::string::npos) {
                out += braille_map[pos] + " ";
            }
        }
    }
}

void braille_decode(std::string a, std::string &out) {
    out = "";
    std::string token;
    bool in_number_mode = false;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            if (token == NUMBER_INDICATOR) {
                in_number_mode = true;  // switch to digit mode
            } else if (token == LETTER_INDICATOR) {
                in_number_mode = false; // switch back to letter mode
            } else if (token == "000000") {
                out += ' ';
                in_number_mode = false; // space resets number mode
            } else if (in_number_mode) {
                // find matching digit
                for (int i = 0; i < 10; i++) {
                    if (digit_map[i] == token) {
                        out += (char)('0' + i);
                        break;
                    }
                }
            } else {
                // find matching letter
                for (int i = 0; i < 27; i++) {
                    if (braille_map[i] == token) {
                        out += braille_alphabet[i];
                        break;
                    }
                }
            }
            token = "";
        } else {
            token += c;
        }
    }
}

void columnar_encrypt(const std::string &a, std::string &out, const std::string &key) {
    out = "";
    int cols = key.length();
    int rows = (a.length() + cols - 1) / cols;
    int total = rows * cols;
    std::string padded = a;
    while ((int)padded.length() < total) padded += 'x';
    std::string sorted_key = key;
    for (int i = 0; i < cols-1; i++)
        for (int j = 0; j < cols-i-1; j++)
            if (sorted_key[j] > sorted_key[j+1])
                std::swap(sorted_key[j], sorted_key[j+1]);
    std::string used(cols, '0');
    int order[cols];
    for (int i = 0; i < cols; i++) {
        for (int j = 0; j < cols; j++) {
            if (key[j] == sorted_key[i] && used[j] == '0') {
                order[i] = j;
                used[j] = '1';
                break;
            }
        }
    }
    for (int i = 0; i < cols; i++) {
        int col = order[i];
        for (int row = 0; row < rows; row++) {
            out += padded[row * cols + col];
        }
    }
}

void columnar_decrypt(const std::string &a, std::string &out, const std::string &key) {
    out = "";
    int cols = key.length();
    int rows = a.length() / cols;
    int total = rows * cols;
    int padded_len = total; // encrypted length is already exact

    std::string sorted_key = key;
    for (int i = 0; i < cols-1; i++)
        for (int j = 0; j < cols-i-1; j++)
            if (sorted_key[j] > sorted_key[j+1])
                std::swap(sorted_key[j], sorted_key[j+1]);

    std::string used(cols, '0');
    int order[cols];
    for (int i = 0; i < cols; i++) {
        for (int j = 0; j < cols; j++) {
            if (key[j] == sorted_key[i] && used[j] == '0') {
                order[i] = j;
                used[j] = '1';
                break;
            }
        }
    }

    std::string grid(total, ' ');
    for (int i = 0; i < cols; i++) {
        int col = order[i];
        for (int row = 0; row < rows; row++) {
            grid[row * cols + col] = a[i * rows + row];
        }
    }

    // count trailing padding x's added during encrypt
    // encrypt pads to fill the grid, so at most cols-1 x's at the end
    int pad_count = 0;
    for (int i = total - 1; i >= total - cols + 1 && grid[i] == 'x'; i--)
        pad_count++;

    for (int i = 0; i < total - pad_count; i++)
        out += grid[i];
}

//rot8000 functions, entirely ai for display

// encode a single unicode codepoint to utf8 bytes
void codepoint_to_utf8(unsigned int cp, std::string &out) {
    if (cp <= 0x7F) {
        out += (char)cp;
    } else if (cp <= 0x7FF) {
        out += (char)(0xC0 | (cp >> 6));
        out += (char)(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
        out += (char)(0xE0 | (cp >> 12));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    } else {
        out += (char)(0xF0 | (cp >> 18));
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    }
}

// decode utf8 bytes to a single unicode codepoint
unsigned int utf8_to_codepoint(const std::string &a, int &i) {
    int n = (int)a.length();
    unsigned char c = (unsigned char)a[i];
    if (c <= 0x7F) {
        return c;
    } else if ((c & 0xE0) == 0xC0) {
        if (i + 1 >= n) { return 0xFFFD; }
        unsigned int cp = (c & 0x1F) << 6;
        cp |= ((unsigned char)a[++i] & 0x3F);
        return cp;
    } else if ((c & 0xF0) == 0xE0) {
        if (i + 2 >= n) { i += (n - i - 1); return 0xFFFD; }
        unsigned int cp = (c & 0x0F) << 12;
        cp |= ((unsigned char)a[++i] & 0x3F) << 6;
        cp |= ((unsigned char)a[++i] & 0x3F);
        return cp;
    } else {
        if (i + 3 >= n) { i += (n - i - 1); return 0xFFFD; }
        unsigned int cp = (c & 0x07) << 18;
        cp |= ((unsigned char)a[++i] & 0x3F) << 12;
        cp |= ((unsigned char)a[++i] & 0x3F) << 6;
        cp |= ((unsigned char)a[++i] & 0x3F);
        return cp;
    }
}

// rotate a single codepoint by key, encrypt or decrypt
unsigned int rot8000_cp(unsigned int cp, int key, bool encrypt) {
    // normalize key to always be positive and within range
    // add large multiple of range to avoid negative modulo
    int k26 = ((key % 26) + 26) % 26;  // normalized for 26-char ranges
    int k25 = ((key % 25) + 25) % 25;  // normalized for 25-char greek ranges
    int k10 = ((key % 10) + 10) % 10;  // normalized for digits

    if (!encrypt) {
        // decrypt: reverse the shift
        k26 = (26 - k26) % 26;
        k25 = (25 - k25) % 25;
        k10 = (10 - k10) % 10;
    }

    // latin uppercase A-Z
    if (cp >= 0x41 && cp <= 0x5A)
        return 0x41 + (cp - 0x41 + k26) % 26;
    // latin lowercase a-z
    if (cp >= 0x61 && cp <= 0x7A)
        return 0x61 + (cp - 0x61 + k26) % 26;
    // greek uppercase Α-Ω
    if (cp >= 0x0391 && cp <= 0x03A9)
        return 0x0391 + (cp - 0x0391 + k25) % 25;
    // greek lowercase α-ω
    if (cp >= 0x03B1 && cp <= 0x03C9)
        return 0x03B1 + (cp - 0x03B1 + k25) % 25;
    // circled uppercase Ⓐ-Ⓩ
    if (cp >= 0x24B6 && cp <= 0x24CF)
        return 0x24B6 + (cp - 0x24B6 + k26) % 26;
    // circled lowercase ⓐ-ⓩ
    if (cp >= 0x24D0 && cp <= 0x24E9)
        return 0x24D0 + (cp - 0x24D0 + k26) % 26;
    // digits 0-9
    if (cp >= 0x30 && cp <= 0x39)
        return 0x30 + (cp - 0x30 + k10) % 10;
    // everything else unchanged
    return cp;
}

void rot8000(const std::string &a, std::string &out, int key, bool encrypt) {
    out = "";
    for (int i = 0; i < (int)a.length(); i++) {
        unsigned int cp = utf8_to_codepoint(a, i);
        unsigned int rotated = rot8000_cp(cp, key, encrypt);
        codepoint_to_utf8(rotated, out);
    }
}

// little endian: least significant byte first, supports multi-byte
void little_endian_encode(long long val, std::string &out, int bytes) {
    out = "";
    for (int i = 0; i < bytes; i++) {
        std::string part;
        base_convert((long long)(val & 0xFF), part, 16);
        if ((int)part.length() < 2) part = "0" + part;
        out += part + " ";
        val >>= 8;  // shift right by 8 bits to get next byte
    }
}

// big endian: most significant byte first, supports multi-byte
void big_endian_encode(long long val, std::string &out, int bytes) {
    out = "";
    // collect bytes first then reverse
    std::string temp = "";
    long long v = val;
    for (int i = 0; i < bytes; i++) {
        std::string part;
        base_convert((long long)(v & 0xFF), part, 16);
        if ((int)part.length() < 2) part = "0" + part;
        temp = part + " " + temp;  // prepend so MSB ends up first
        v >>= 8;
    }
    out = temp;
}

// decode little endian hex string back to value
void little_endian_decode(const std::string &a, long long &out) {
    out = 0;
    std::string token;
    int shift = 0;
    for (char c : a + " ") {
        if (c == ' ') {
            if (token.empty()) continue;
            long long byte_val;
            base_deconvert(token, byte_val, 16);
            out |= (byte_val << shift);  // place byte at correct position
            shift += 8;
            token = "";
        } else {
            token += c;
        }
    }
}

// decode big endian hex string back to value
void big_endian_decode(const std::string &a, long long &out) {
    out = 0;
    std::string token;
    // collect all tokens first
    std::string tokens[64];
    int count = 0;
    std::string t;
    for (char c : a + " ") {
        if (c == ' ') {
            if (t.empty()) continue;
            tokens[count++] = t;
            t = "";
        } else {
            t += c;
        }
    }
    // read MSB first
    for (int i = 0; i < count; i++) {
        long long byte_val;
        base_deconvert(tokens[i], byte_val, 16);
        out = (out << 8) | byte_val;
    }
}

void a1z26(const std::string &a, std::string &out){
    for (char c:a){
        bool upper=true;
        bool alphanr=false;
        int d=c;
        if(d>=97 && d<=122){
            upper=false;
            alphanr=true;
        }
        if(d>=65 && d<=90){
            upper=true;
            alphanr=true;
        }
        if(!upper && alphanr){
            out+=std::to_string(d-96);
            out+='-';
        }
        else if(upper && alphanr){ out+=std::to_string(d-64); out+='-';}
        else out+=c;
    }
}
