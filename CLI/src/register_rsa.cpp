#include "../includes/register_handlers.h"
#include "../includes/ntl_bridge.h"
#include "../includes/bigint.hpp"
#include <NTL/ZZ.h>
#include <signal.h>
#include <unistd.h>
#include <future>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <thread>

NTL_CLIENT

static ZZ zz_from_hex(const std::string &s) {
    std::string h = s;
    if (h.empty()) return ZZ::zero();
    ZZ r = ZZ::zero();
    for (size_t i = 0; i < h.size(); i++) {
        r *= 16;
        char c = h[i];
        if (c >= '0' && c <= '9')       r += (c - '0');
        else if (c >= 'a' && c <= 'f')  r += (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')  r += (c - 'A' + 10);
    }
    return r;
}

static ZZ zz_from_auto(const std::string &s) {
    std::string h = s;
    if (h.empty()) return ZZ::zero();
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
        return zz_from_hex(h.substr(2));
    bool has_hex = false;
    for (char c : h) {
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            has_hex = true;
            break;
        }
    }
    if (has_hex) return zz_from_hex(h);
    return conv<ZZ>(h.c_str());
}

static std::string zz_to_hex(const ZZ &z) {
    if (z == 0) return "0";
    std::string h;
    ZZ tmp = z;
    while (tmp > 0) {
        long d = conv<long>(tmp % 16);
        if (d < 10) h = char('0' + d) + h;
        else        h = char('a' + d - 10) + h;
        tmp /= 16;
    }
    return h;
}

static std::string strip_0x(const std::string &s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return s.substr(2);
    return s;
}

static BigInt bigint_sqrt(const BigInt &n) {
    if (n == BigInt(0)) return BigInt(0);
    BigInt x = n;
    BigInt two(2);
    BigInt y = (x + n / x) / two;
    while (y < x) {
        x = y;
        y = (x + n / x) / two;
    }
    return x;
}

static BigInt bigint_gcd(const BigInt &a, const BigInt &b, BigInt &x, BigInt &y) {
    if (b == BigInt(0)) { x = BigInt(1); y = BigInt(0); return a; }
    BigInt x1, y1;
    BigInt g = bigint_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

static BigInt bigint_iabs(const BigInt &n) {
    BigInt r = n;
    r.negative = false;
    return r;
}

static BigInt bigint_pollard_rho(const BigInt &n) {
    if (n % BigInt(2) == BigInt(0)) return BigInt(2);
    BigInt x(2), y(2), d(1);
    auto f = [&n](const BigInt &v) { return (v * v + BigInt(1)) % n; };
    while (d == BigInt(1)) {
        x = f(x);
        y = f(f(y));
        BigInt diff = (x.negative != y.negative)
            ? bigint_iabs(x) + bigint_iabs(y)
            : (x < y) ? bigint_iabs(y - x) : bigint_iabs(x - y);
        BigInt a = diff, b = n;
        while (b != BigInt(0)) {
            BigInt t = b;
            b = a % b;
            a = t;
        }
        d = a;
    }
    return d;
}

static void print_rsa_result(const std::string &m_hex, bool raw) {
    std::string m_bytes = hex_decode_str(m_hex);
    size_t pos = 0;
    if (m_bytes.size() >= 12 && (unsigned char)m_bytes[0] == 0x00
        && (unsigned char)m_bytes[1] == 0x02) {
        bool valid = false;
        for (size_t i = 2; i + 1 < m_bytes.size(); i++) {
            if ((unsigned char)m_bytes[i] == 0x00) {
                if (i - 2 >= 8) valid = true;
                break;
            }
        }
        if (valid) {
            for (size_t i = 2; i < m_bytes.size() - 1; i++) {
                if ((unsigned char)m_bytes[i] == 0x00) {
                    pos = i + 1;
                    break;
                }
            }
        }
    }
    std::string plaintext = (pos > 0 && pos < m_bytes.size())
        ? m_bytes.substr(pos) : m_bytes;
    bool printable = true;
    for (unsigned char c : plaintext)
        if (c < 32 && c != '\n' && c != '\t' && c != '\r') { printable = false; break; }
    if (printable) {
        std::cout << plaintext;
    } else {
        std::string raw_hex;
        for (unsigned char c : m_bytes) {
            std::string h;
            base_convert((long long)c, h, 16);
            if (h.size() == 1) raw_hex += '0';
            raw_hex += h;
        }
        std::cout << "[hex] " << raw_hex;
    }
    if (!raw) std::cout << "\n";
}

void register_rsa_handlers(HandlerMap &map) {

    // ── RSA Decrypt ──
    map["rsa-decrypt"] = [](const Context &ctx) {
        std::string c_hex = ctx.flag("-c");
        std::string d_hex = ctx.flag("-d");
        std::string n_hex = ctx.flag("-n");
        std::string m_hex, err;
        if (!ntl_rsa_decrypt(c_hex, d_hex, n_hex, m_hex, err))
            throw CipherError(std::string("rsa-decrypt: ") + err);
        print_rsa_result(m_hex, ctx.raw);
    };

    // ── RSA Wiener ──
    map["rsa-wiener"] = [](const Context &ctx) {
        std::string e_hex = ctx.flag("-e");
        std::string n_hex = ctx.flag("-n");
        std::string c_hex = ctx.opt_flag("-c", "");
        std::string d_hex, p_hex, q_hex, err;
        if (!ntl_rsa_wiener(e_hex, n_hex, d_hex, p_hex, q_hex, err))
            throw CipherError(std::string("rsa-wiener: ") + err);
        BigInt d_big = BigInt::from_hex(d_hex);
        std::cout << "d (hex): " << d_hex << "\n";
        std::cout << "d (dec): " << d_big.toString() << "\n";
        if (!p_hex.empty()) {
            BigInt p = BigInt::from_hex(p_hex);
            BigInt q = BigInt::from_hex(q_hex);
            std::cout << "p (hex): " << p_hex << "\n";
            std::cout << "q (hex): " << q_hex << "\n";
            if (!c_hex.empty()) {
                c_hex = strip_0x(c_hex);
                BigInt c = BigInt::from_auto(c_hex);
                BigInt one(1ULL);
                BigInt dp = d_big % (p - one);
                BigInt dq = d_big % (q - one);
                BigInt qinv = q.modinv(p);
                BigInt m = rsa_crt_decrypt(c, p, q, dp, dq, qinv);
                std::cout << "plaintext: ";
                print_rsa_result(m.toHex(), ctx.raw);
            } else {
                std::cout << "(use -c <hex> to decrypt with CRT)\n";
            }
        }
    };

    // ── RSA Hastad ──
    map["rsa-hastad"] = [](const Context &ctx) {
        int e = ctx.int_flag("-e");
        std::string c_arg = ctx.flag("--ciphertexts");
        std::string n_arg = ctx.flag("--moduli");
        auto split_csv = [](const std::string &s) {
            std::vector<std::string> parts;
            std::string cur;
            for (char ch : s) {
                if (ch == ',') {
                    if (!cur.empty()) { parts.push_back(cur); cur.clear(); }
                } else {
                    cur += ch;
                }
            }
            if (!cur.empty()) parts.push_back(cur);
            return parts;
        };
        auto c_list = split_csv(c_arg);
        auto n_list = split_csv(n_arg);
        if ((int)c_list.size() < e || (int)n_list.size() < e)
            throw CipherError("rsa-hastad: need at least e ciphertext/modulus pairs");
        std::string m_hex, err;
        if (!ntl_rsa_hastad(c_list, n_list, e, m_hex, err))
            throw CipherError(std::string("rsa-hastad: ") + err);
        print_rsa_result(m_hex, ctx.raw);
    };

    // ── RSA Common Modulus ──
    map["rsa-common-modulus"] = [](const Context &ctx) {
        std::string n_str = strip_0x(ctx.flag("-n"));
        std::string e1_str = strip_0x(ctx.flag("-e1"));
        std::string e2_str = strip_0x(ctx.flag("-e2"));
        std::string c1_str = strip_0x(ctx.flag("-c1"));
        std::string c2_str = strip_0x(ctx.flag("-c2"));
        BigInt n = BigInt::from_auto(n_str);
        BigInt e1 = BigInt::from_auto(e1_str);
        BigInt e2 = BigInt::from_auto(e2_str);
        BigInt c1 = BigInt::from_auto(c1_str);
        BigInt c2 = BigInt::from_auto(c2_str);
        BigInt s1, s2;
        BigInt g = bigint_gcd(e1, e2, s1, s2);
        if (g != BigInt(1))
            throw CipherError("rsa-common-modulus: e1 and e2 are not coprime");
        BigInt m;
        if (s1.negative) {
            BigInt inv = c1.modinv(n);
            BigInt abs_s1 = s1; abs_s1.negative = false;
            m = inv.modexp(abs_s1, n);
        } else {
            m = c1.modexp(s1, n);
        }
        if (s2.negative) {
            BigInt inv = c2.modinv(n);
            BigInt abs_s2 = s2; abs_s2.negative = false;
            m = m * inv.modexp(abs_s2, n) % n;
        } else {
            m = m * c2.modexp(s2, n) % n;
        }
        print_rsa_result(m.toHex(), ctx.raw);
    };

    // ── RSA Fermat Factor ──
    map["rsa-factor-fermat"] = [](const Context &ctx) {
        std::string n_str = strip_0x(ctx.flag("-n"));
        BigInt n = BigInt::from_auto(n_str);
        BigInt a = bigint_sqrt(n);
        if (a * a < n) a = a + BigInt(1);
        BigInt one(1);
        bool found = false;
        for (int iter = 0; iter < 100000; iter++) {
            BigInt b2 = a * a - n;
            BigInt b = bigint_sqrt(b2);
            if (b * b == b2) {
                BigInt p = a - b;
                BigInt q = a + b;
                if (p * q == n) {
                    std::cout << "p (hex): " << p.toHex() << "\n";
                    std::cout << "p (dec): " << p.toString() << "\n";
                    std::cout << "q (hex): " << q.toHex() << "\n";
                    std::cout << "q (dec): " << q.toString() << "\n";
                    found = true;
                    break;
                }
            }
            a = a + one;
        }
        if (!found)
            throw CipherError("rsa-factor-fermat: failed to factor (primes not close enough)");
    };

    // ── RSA Pollard Rho ──
    map["rsa-factor-pollard"] = [](const Context &ctx) {
        std::string n_str = strip_0x(ctx.flag("-n"));
        BigInt n = BigInt::from_auto(n_str);
        BigInt f = bigint_pollard_rho(n);
        if (f == BigInt(0) || f == n)
            throw CipherError("rsa-factor-pollard: failed to find factor");
        BigInt q = n / f;
        std::cout << "p (hex): " << f.toHex() << "\n";
        std::cout << "p (dec): " << f.toString() << "\n";
        std::cout << "q (hex): " << q.toHex() << "\n";
        std::cout << "q (dec): " << q.toString() << "\n";
    };

    // ── RSA Parity Oracle ──
    map["rsa-parity-oracle"] = [](const Context &ctx) {
        std::string n_hex = ctx.flag("-n");
        std::string e_hex = ctx.flag("-e");
        std::string oracle_cmd = ctx.flag("--oracle");
        int timeout_ms = ctx.opt_int_flag("--timeout", 5000);
        ZZ n = zz_from_auto(n_hex);
        ZZ e = zz_from_auto(e_hex);
        std::string c_hex;
        {
            size_t ii = 0;
            while (ii < ctx.args.size()) {
                if (ctx.args[ii] == "-c" && ii + 1 < ctx.args.size()) {
                    c_hex = strip_0x(ctx.args[ii + 1]); break;
                }
                ii++;
            }
        }
        if (c_hex.empty()) throw CipherError("rsa-parity-oracle: missing -c <ciphertext_hex>");
        ZZ ct = zz_from_auto(c_hex);
        ZZ lo = ZZ(0), hi = n;
        ZZ two(2);
        ZZ pow2e;
        PowerMod(pow2e, two, e, n);
        int bits = NumBits(n);
        for (int i = 0; i < bits; i++) {
            if (i > 0) {
                PowerMod(ct, ct * pow2e, 1, n);
            } else {
                PowerMod(ct, ct, 1, n);
            }
            std::string query_hex = zz_to_hex(ct);
            auto future = std::async(std::launch::async, [oracle_cmd, query_hex]() {
                std::string shell_cmd = "echo '" + query_hex + "' | " + oracle_cmd;
                FILE *fp = popen(shell_cmd.c_str(), "r");
                if (!fp) return std::string("<error>");
                std::string result;
                char buf[256];
                while (fgets(buf, sizeof(buf), fp)) result += buf;
                pclose(fp);
                while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
                    result.pop_back();
                return result;
            });
            if (future.wait_for(std::chrono::milliseconds(timeout_ms))
                == std::future_status::timeout) {
                throw CipherError("rsa-parity-oracle: oracle query timed out");
            }
            std::string oracle_resp = future.get();
            if (oracle_resp == "<error>")
                throw CipherError("rsa-parity-oracle: failed to run oracle command");
            bool is_even = (!oracle_resp.empty() && oracle_resp[0] == '0');
            ZZ mid = (lo + hi) / 2;
            if (is_even)
                hi = mid;
            else
                lo = mid;
        }
        print_rsa_result(zz_to_hex(hi), ctx.raw);
    };

    // ── RSA Encode ──
    map["rsa-encode"] = [](const Context &ctx) {
        std::string e_str = strip_0x(ctx.flag("-e"));
        std::string n_str = strip_0x(ctx.flag("-n"));
        BigInt e = BigInt::from_auto(e_str);
        BigInt n = BigInt::from_auto(n_str);
        std::string input = ctx.input;
        std::string m_hex;
        for (unsigned char ch : input) {
            std::string h;
            base_convert((long long)ch, h, 16);
            if (h.size() == 1) m_hex += '0';
            m_hex += h;
        }
        BigInt m = BigInt::from_hex(m_hex);
        BigInt ct = m.modexp(e, n);
        std::cout << ct.toHex();
        if (!ctx.raw) std::cout << "\n";
    };

    // ── RSA Info ──
    map["rsa-info"] = [](const Context &ctx) {
        std::string n_str = strip_0x(ctx.flag("-n"));
        std::string e_str = ctx.opt_flag("-e", "010001");
        e_str = strip_0x(e_str);
        ZZ n = zz_from_auto(n_str);
        ZZ e = zz_from_auto(e_str);
        long nbits = NumBits(n);
        std::cout << "Key size: " << nbits << " bits\n";
        std::cout << "n (dec): " << n << "\n";
        std::cout << "e: 0x" << e_str << " (";
        if (e == 3) {
            std::cout << "Hastad BROADCAST ATTACK RISK";
        } else if (e == 65537) {
            std::cout << "standard (recommended)";
        } else if (e < 65537) {
            std::cout << "small exponent — may be vulnerable";
        } else {
            std::cout << "non-standard large exponent";
        }
        std::cout << ")\n";
        ZZ n_sqrt;
        SqrRoot(n_sqrt, n);
        ZZ bound = n_sqrt / 2;
        ZZ d_est;
        PowerMod(d_est, bound, e, n);
        std::cout << "Wiener estimate: d < n^0.25 ≈ " << nbits / 4 << " bits";
        if (nbits < 2048) {
            std::cout << " — LIKELY VULNERABLE for small d\n";
        } else {
            std::cout << " — safe for 2048+ with proper d\n";
        }
        if (n % ZZ(3) == 0) {
            std::cout << "WARNING: n is divisible by 3 (trivially factorable!)\n";
        }
        if (n % ZZ(5) == 0) {
            std::cout << "WARNING: n is divisible by 5 (trivially factorable!)\n";
        }
        if (nbits < 1024) {
            std::cout << "Factorization difficulty: WEAK ("
                      << nbits << " bits — factorable in minutes)\n";
        } else if (nbits < 2048) {
            std::cout << "Factorization difficulty: MODERATE ("
                      << nbits << " bits — potentially factorable with resources)\n";
        } else {
            std::cout << "Factorization difficulty: STRONG ("
                      << nbits << " bits — secure with proper primes)\n";
        }
        if (!ctx.raw) std::cout << std::flush;
    };

    // ── EC Add ──
    map["ec-add"] = [](const Context &ctx) {
        std::string x1 = ctx.flag("--x1"), y1 = ctx.flag("--y1");
        std::string x2 = ctx.flag("--x2"), y2 = ctx.flag("--y2");
        std::string a = ctx.flag("--a"), p = ctx.flag("--p");
        std::string xr, yr, err;
        if (!ntl_ec_add(x1, y1, x2, y2, a, p, xr, yr, err))
            throw CipherError(std::string("ec-add: ") + err);
        std::cout << "x: " << xr << "\ny: " << yr << "\n";
    };

    // ── EC Scalar Mul ──
    map["ec-mul"] = [](const Context &ctx) {
        std::string k = ctx.flag("--k");
        std::string x = ctx.flag("--x"), y = ctx.flag("--y");
        std::string a = ctx.flag("--a"), p = ctx.flag("--p");
        std::string xr, yr, err;
        if (!ntl_ec_scalar_mul(k, x, y, a, p, xr, yr, err))
            throw CipherError(std::string("ec-mul: ") + err);
        std::cout << "x: " << xr << "\ny: " << yr << "\n";
    };

    // ── DLP BSGS ──
    map["dlp-bsgs"] = [](const Context &ctx) {
        std::string g = ctx.flag("--g"), hstr = ctx.flag("--h");
        std::string p = ctx.flag("--p");
        std::string x_hex, err;
        if (!ntl_bsgs(g, hstr, p, x_hex, err))
            throw CipherError(std::string("dlp-bsgs: ") + err);
        std::cout << "x (hex): " << x_hex << "\n";
        std::cout << "x (dec): " << BigInt::from_hex(x_hex).toString() << "\n";
    };

    // ── DLP Pohlig-Hellman ──
    map["dlp-pohlig"] = [](const Context &ctx) {
        std::string g = ctx.flag("--g"), hstr = ctx.flag("--h");
        std::string p = ctx.flag("--p");
        std::string x_hex, err;
        if (!ntl_pohlig_hellman(g, hstr, p, x_hex, err))
            throw CipherError(std::string("dlp-pohlig: ") + err);
        std::cout << "x (hex): " << x_hex << "\n";
        std::cout << "x (dec): " << BigInt::from_hex(x_hex).toString() << "\n";
    };

    // ── LLL ──
    map["lll"] = [](const Context &ctx) {
        std::string matrix_str = ctx.flag("--matrix");
        if (matrix_str.size() < 2 || matrix_str[0] != '[' || matrix_str.back() != ']')
            throw CipherError("lll: matrix must be in JSON-like format [[a,b],[c,d]]");
        std::vector<std::vector<std::string>> rows;
        size_t pos = 1;
        while (pos < matrix_str.size() - 1) {
            if (matrix_str[pos] == '[') {
                pos++;
                std::vector<std::string> row;
                std::string cur;
                while (pos < matrix_str.size() && matrix_str[pos] != ']') {
                    if (matrix_str[pos] == ',' || matrix_str[pos] == ' ') {
                        if (!cur.empty()) { row.push_back(cur); cur.clear(); }
                        if (matrix_str[pos] == ',') { pos++; break; }
                        pos++;
                        continue;
                    }
                    cur += matrix_str[pos];
                    pos++;
                }
                if (!cur.empty()) row.push_back(cur);
                if (!row.empty()) rows.push_back(row);
                while (pos < matrix_str.size() && matrix_str[pos] != ']') pos++;
                if (pos < matrix_str.size()) pos++;
                while (pos < matrix_str.size()
                       && (matrix_str[pos] == ',' || matrix_str[pos] == ' ')) pos++;
            } else {
                pos++;
            }
        }
        if (rows.empty())
            throw CipherError("lll: could not parse matrix");
        std::vector<std::vector<std::string>> out_hex;
        std::string err;
        if (!ntl_lll(rows, out_hex, err))
            throw CipherError(std::string("lll: ") + err);
        std::cout << "[\n";
        for (size_t i = 0; i < out_hex.size(); i++) {
            std::cout << "  [";
            for (size_t j = 0; j < out_hex[i].size(); j++) {
                if (j > 0) std::cout << ", ";
                std::cout << out_hex[i][j];
            }
            std::cout << "]";
            if (i + 1 < out_hex.size()) std::cout << ",";
            std::cout << "\n";
        }
        std::cout << "]\n";
    };
}
