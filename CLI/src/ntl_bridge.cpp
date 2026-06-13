#include "../includes/ntl_bridge.h"
#include <NTL/ZZ.h>
#include <NTL/LLL.h>
#include <NTL/mat_ZZ.h>
#include <map>
#include <vector>
#include <string>
#include <utility>
#include <cstdlib>

NTL_CLIENT

// ── helpers ──

static ZZ zz_from_hex_raw(const std::string &s) {
    if (s.empty()) return ZZ::zero();
    ZZ r = ZZ::zero();
    for (size_t i = 0; i < s.size(); i++) {
        r *= 16;
        char c = s[i];
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
        return zz_from_hex_raw(h.substr(2));
    bool has_hex = false;
    for (char c : h) {
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            has_hex = true;
            break;
        }
    }
    if (has_hex) return zz_from_hex_raw(h);
    return conv<ZZ>(h.c_str());
}

static std::string hex_from_zz(const ZZ &z) {
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

static ZZ zz_root(const ZZ &a, long e) {
    if (e == 1) return a;
    if (e == 2) {
        ZZ r;
        SqrRoot(r, a);
        if (r * r == a) return r;
        return ZZ(-1);
    }
    if (a <= 0) return (a == 0) ? ZZ(0) : ZZ(-1);
    ZZ lo = ZZ(1); ZZ hi = a;
    while (lo < hi) {
        ZZ mid = (lo + hi + 1) / 2;
        ZZ p;
        power(p, mid, e);
        if (p <= a) lo = mid;
        else        hi = mid - 1;
    }
    ZZ p;
    power(p, lo, e);
    if (p == a) return lo;
    return ZZ(-1);
}

// ── RSA decrypt ──

bool ntl_rsa_decrypt(const std::string &c_hex, const std::string &d_hex,
                     const std::string &n_hex, std::string &m_hex,
                     std::string &error_msg) {
    try {
        ZZ c = zz_from_auto(c_hex);
        ZZ d = zz_from_auto(d_hex);
        ZZ n = zz_from_auto(n_hex);
        ZZ m;
        PowerMod(m, c, d, n);
        m_hex = hex_from_zz(m);
        return true;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}

// ── Wiener's continued-fraction attack ──

bool ntl_rsa_wiener(const std::string &e_hex, const std::string &n_hex,
                    std::string &d_hex, std::string &p_hex, std::string &q_hex,
                    std::string &error_msg) {
    try {
        ZZ e = zz_from_auto(e_hex);
        ZZ n = zz_from_auto(n_hex);

        std::vector<ZZ> cf;
        ZZ num = e, den = n, rem;
        while (den != 0) {
            ZZ quot = num / den;
            rem = num % den;
            cf.push_back(quot);
            num = den;
            den = rem;
        }

        ZZ h_prev2 = ZZ(0), h_prev1 = ZZ(1);
        ZZ k_prev2 = ZZ(1), k_prev1 = ZZ(0);

        for (size_t i = 0; i < cf.size(); i++) {
            ZZ h = cf[i] * h_prev1 + h_prev2;
            ZZ k = cf[i] * k_prev1 + k_prev2;

            if (k > 0 && bit(k, 0) == 1) {
                ZZ edm1 = e * k - 1;
                if (h != 0 && edm1 % h == 0) {
                    ZZ phi = edm1 / h;
                    ZZ sum_pq = n - phi + 1;
                    if (sum_pq > 0) {
                        ZZ disc = sum_pq * sum_pq - 4 * n;
                        if (disc > 0) {
                            ZZ sd;
                            SqrRoot(sd, disc);
                            if (sd * sd == disc) {
                                d_hex = hex_from_zz(k);
                                ZZ p = (sum_pq - sd) / 2;
                                ZZ q = (sum_pq + sd) / 2;
                                if (p * q == n) {
                                    p_hex = hex_from_zz(p);
                                    q_hex = hex_from_zz(q);
                                }
                                return true;
                            }
                        }
                    }
                }
            }

            h_prev2 = h_prev1;
            h_prev1 = h;
            k_prev2 = k_prev1;
            k_prev1 = k;
        }

        error_msg = "Wiener attack failed: no suitable convergent";
        return false;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}

// ── Hastad broadcast attack ──

bool ntl_rsa_hastad(const std::vector<std::string> &c_hex_list,
                    const std::vector<std::string> &n_hex_list, int e,
                    std::string &m_hex, std::string &error_msg) {
    try {
        size_t k = c_hex_list.size();
        if (k != n_hex_list.size() || k < (size_t)e) {
            error_msg = "Hastad: need at least e ciphertext/modulus pairs";
            return false;
        }

        std::vector<ZZ> c_list, n_list;
        for (size_t i = 0; i < k; i++) {
            c_list.push_back(zz_from_auto(c_hex_list[i]));
            n_list.push_back(zz_from_auto(n_hex_list[i]));
        }

        ZZ N = ZZ(1);
        for (size_t i = 0; i < k; i++) N *= n_list[i];

        ZZ result = ZZ(0);
        for (size_t i = 0; i < k; i++) {
            ZZ Ni = N / n_list[i];
            ZZ Mi;
            InvMod(Mi, Ni % n_list[i], n_list[i]);
            result += c_list[i] * Ni * Mi;
        }
        result %= N;

        ZZ m = zz_root(result, e);
        if (m < 0) {
            error_msg = "Hastad: result is not a perfect e-th power";
            return false;
        }

        m_hex = hex_from_zz(m);
        return true;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}

// ── EC point addition (y^2 = x^3 + ax + b mod p) ──

bool ntl_ec_add(const std::string &x1_hex, const std::string &y1_hex,
                const std::string &x2_hex, const std::string &y2_hex,
                const std::string &a_hex, const std::string &p_hex,
                std::string &xr_hex, std::string &yr_hex,
                std::string &error_msg) {
    try {
        ZZ x1 = zz_from_auto(x1_hex);
        ZZ y1 = zz_from_auto(y1_hex);
        ZZ x2 = zz_from_auto(x2_hex);
        ZZ y2 = zz_from_auto(y2_hex);
        ZZ a  = zz_from_auto(a_hex);
        ZZ p  = zz_from_auto(p_hex);

        ZZ x3, y3, lam, num, den, den_inv;

        if (x1 == x2) {
            if (y1 != y2) {
                error_msg = "EC add: point at infinity (P + (-P))";
                return false;
            }
            if (y1 == 0) {
                error_msg = "EC add: point at infinity (2 * point with y=0)";
                return false;
            }
            num = (3 * x1 * x1 + a) % p;
            den = (2 * y1) % p;
            InvMod(den_inv, den, p);
            lam = (num * den_inv) % p;
            x3 = (lam * lam - x1 - x2) % p;
            y3 = (lam * (x1 - x3) - y1) % p;
        } else {
            num = (y2 - y1) % p;
            den = (x2 - x1) % p;
            InvMod(den_inv, den, p);
            lam = (num * den_inv) % p;
            x3 = (lam * lam - x1 - x2) % p;
            y3 = (lam * (x1 - x3) - y1) % p;
        }

        if (x3 < 0) x3 += p;
        if (y3 < 0) y3 += p;

        xr_hex = hex_from_zz(x3);
        yr_hex = hex_from_zz(y3);
        return true;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}

// ── EC scalar multiplication (double-and-add) ──

bool ntl_ec_scalar_mul(const std::string &k_hex,
                       const std::string &x_hex, const std::string &y_hex,
                       const std::string &a_hex, const std::string &p_hex,
                       std::string &xr_hex, std::string &yr_hex,
                       std::string &error_msg) {
    try {
        ZZ k  = zz_from_auto(k_hex);
        ZZ xp = zz_from_auto(x_hex);
        ZZ yp = zz_from_auto(y_hex);
        ZZ a  = zz_from_auto(a_hex);
        ZZ p  = zz_from_auto(p_hex);

        ZZ rx = ZZ(0), ry = ZZ(0);
        bool inf = true;

        long bits = NumBits(k);
        for (long i = bits - 1; i >= 0; i--) {
            if (!inf) {
                ZZ num, den, den_inv, lam;
                if (rx == xp && ry == yp) {
                    num = (3 * rx * rx + a) % p;
                    den = (2 * ry) % p;
                } else {
                    num = (yp - ry) % p;
                    den = (xp - rx) % p;
                }
                InvMod(den_inv, den, p);
                lam = (num * den_inv) % p;
                ZZ x3 = (lam * lam - rx - xp) % p;
                ZZ y3 = (lam * (rx - x3) - ry) % p;
                if (x3 < 0) x3 += p;
                if (y3 < 0) y3 += p;
                rx = x3; ry = y3;
            } else {
                rx = xp; ry = yp;
                inf = false;
            }

            if (bit(k, i)) {
                if (!inf) {
                    ZZ num, den, den_inv, lam;
                    num = (3 * rx * rx + a) % p;
                    den = (2 * ry) % p;
                    InvMod(den_inv, den, p);
                    lam = (num * den_inv) % p;
                    ZZ x3 = (lam * lam - rx - rx) % p;
                    ZZ y3 = (lam * (rx - x3) - ry) % p;
                    if (x3 < 0) x3 += p;
                    if (y3 < 0) y3 += p;
                    rx = x3; ry = y3;
                } else {
                    rx = xp; ry = yp;
                    inf = false;
                }
            }
        }

        if (inf) {
            error_msg = "EC scalar mul: result is point at infinity";
            return false;
        }

        xr_hex = hex_from_zz(rx);
        yr_hex = hex_from_zz(ry);
        return true;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}

// ── Baby-step giant-step DLP ──

bool ntl_bsgs(const std::string &g_hex, const std::string &h_hex,
              const std::string &p_hex, std::string &x_hex,
              std::string &error_msg) {
    try {
        ZZ g = zz_from_auto(g_hex);
        ZZ h = zz_from_auto(h_hex);
        ZZ p = zz_from_auto(p_hex);
        ZZ order = p - 1;

        ZZ m;
        SqrRoot(m, order);
        m += 1;

        std::map<ZZ, long> baby;
        ZZ cur = ZZ(1);
        for (long j = 0; j < m; j++) {
            baby[cur] = j;
            cur = (cur * g) % p;
        }

        ZZ inv_g;
        InvMod(inv_g, g, p);
        ZZ giant;
        PowerMod(giant, inv_g, m, p);
        cur = h;
        for (long i = 0; i < m; i++) {
            auto it = baby.find(cur);
            if (it != baby.end()) {
                ZZ x = ZZ(i) * m + it->second;
                x_hex = hex_from_zz(x);
                return true;
            }
            cur = (cur * giant) % p;
        }

        error_msg = "BSGS: discrete log not found";
        return false;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}

// ── Pohlig-Hellman DLP ──

static std::vector<std::pair<ZZ, long>> trial_factor(ZZ n, ZZ limit) {
    std::vector<std::pair<ZZ, long>> factors;
    for (ZZ q = ZZ(2); q * q <= n && q <= limit; q++) {
        if (n % q == 0) {
            long e = 0;
            while (n % q == 0) { n /= q; e++; }
            factors.push_back(std::make_pair(q, e));
        }
    }
    if (n > 1) factors.push_back(std::make_pair(n, 1));
    return factors;
}

static ZZ bsgs_small(const ZZ &g, const ZZ &h, const ZZ &p, const ZZ &bound) {
    ZZ m;
    SqrRoot(m, bound);
    m += 1;

    std::map<ZZ, long> baby;
    ZZ cur = ZZ(1);
    for (long j = 0; j < m; j++) {
        baby[cur] = j;
        cur = (cur * g) % p;
    }

    ZZ inv_g;
    InvMod(inv_g, g, p);
    ZZ giant;
    PowerMod(giant, inv_g, m, p);
    cur = h;
    for (long i = 0; i < m; i++) {
        auto it = baby.find(cur);
        if (it != baby.end())
            return ZZ(i) * m + it->second;
        cur = (cur * giant) % p;
    }
    return ZZ(-1);
}

bool ntl_pohlig_hellman(const std::string &g_hex, const std::string &h_hex,
                        const std::string &p_hex, std::string &x_hex,
                        std::string &error_msg) {
    try {
        ZZ g = zz_from_auto(g_hex);
        ZZ h = zz_from_auto(h_hex);
        ZZ p = zz_from_auto(p_hex);
        ZZ order = p - 1;

        std::vector<std::pair<ZZ, long>> factors = trial_factor(order, ZZ(1000000));
        ZZ check = ZZ(1);
        for (auto &f : factors)
            for (long i = 0; i < f.second; i++)
                check *= f.first;

        if (check != order) {
            error_msg = "Pohlig-Hellman: order has a large unfactored factor";
            return false;
        }

        std::vector<ZZ> remainders, moduli;

        for (auto &f : factors) {
            ZZ q = f.first;
            long e = f.second;
            ZZ qe;
            power(qe, q, e);

            ZZ gi;
            PowerMod(gi, g, order / qe, p);
            ZZ hi;
            PowerMod(hi, h, order / qe, p);

            ZZ xi = bsgs_small(gi, hi, p, qe);
            if (xi < 0) {
                error_msg = "Pohlig-Hellman: BSGS failed in a subgroup";
                return false;
            }

            remainders.push_back(xi);
            moduli.push_back(qe);
        }

        ZZ result = ZZ(0), M = ZZ(1);
        for (size_t i = 0; i < moduli.size(); i++) {
            ZZ Mi = M;
            ZZ Mi_inv;
            InvMod(Mi_inv, Mi % moduli[i], moduli[i]);
            result += remainders[i] * Mi * Mi_inv;
            M *= moduli[i];
        }
        result %= M;

        x_hex = hex_from_zz(result);
        return true;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}

// ── LLL lattice reduction ──

bool ntl_lll(const std::vector<std::vector<std::string>> &rows_hex,
             std::vector<std::vector<std::string>> &out_hex,
             std::string &error_msg) {
    try {
        if (rows_hex.empty()) {
            error_msg = "LLL: empty input matrix";
            return false;
        }
        long rows = (long)rows_hex.size();
        long cols = (long)rows_hex[0].size();
        for (long i = 0; i < rows; i++)
            if ((long)rows_hex[i].size() != cols) {
                error_msg = "LLL: rows must have equal length";
                return false;
            }

        Mat<ZZ> M;
        M.SetDims(rows, cols);
        for (long i = 0; i < rows; i++)
            for (long j = 0; j < cols; j++)
                M[i][j] = zz_from_auto(rows_hex[i][j]);

        LLL_FP(M);

        out_hex.clear();
        out_hex.resize(rows);
        for (long i = 0; i < rows; i++) {
            out_hex[i].resize(cols);
            for (long j = 0; j < cols; j++)
                out_hex[i][j] = hex_from_zz(M[i][j]);
        }

        return true;
    } catch (std::exception &e) {
        error_msg = e.what();
        return false;
    }
}
