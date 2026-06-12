// mathutils.cpp — uint64_t-precision arithmetic for small operands only.
// Used for non-RSA operations (e.g. basic key derivation, small-field math).
// For arbitrary-precision crypto (RSA, ECDH) use bigint.cpp instead.
//
// Duplicates: modexp and extended_gcd exist in both this file and bigint.cpp.
//   mathutils.cpp: uint64_t versions  (≤64-bit operands)
//   bigint.cpp:    BigInt versions    (arbitrary precision)
// Do NOT add new crypto primitives here unless they are explicitly uint64_t-only.

#include <cstdint>

uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod==1) return 0;
    uint64_t result=1;
    base=base%mod;
    while (exp>0) {
        if (exp%2==1)
            result=((__uint128_t)result * base) % mod;;
        exp/=2;
        base=((__uint128_t)base * base) % mod;
    }
    return result;
}

uint64_t gcd(uint64_t a, uint64_t b) {
    if (b==0) return a;
    return gcd(b, a%b);
}

int64_t extended_gcd(int64_t a, int64_t b, int64_t& x, int64_t& y) {
    if (b == 0) {
        x = 1; y = 0;
        return a;
    }
    int64_t x1, y1;
    int64_t g=extended_gcd(b, a % b, x1, y1);
    x=y1;
    y=x1-(a/b)*y1;
    return g;
}

uint64_t modinv(uint64_t a, uint64_t mod) {
    int64_t x, y;
    int64_t g=extended_gcd((int64_t)a, (int64_t)mod, x, y);
    if (g!=1) return 0;
    return (uint64_t)(((x % (int64_t)mod) + (int64_t)mod) % (int64_t)mod);
}