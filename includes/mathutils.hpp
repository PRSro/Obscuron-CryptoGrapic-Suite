#ifndef MATHUTILS_H
#define MATHUTILS_H
#include <cstdint>

uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod);  // fast exponentiation
uint64_t gcd(uint64_t a, uint64_t b);                        // euclidean gcd
int64_t extended_gcd(int64_t a, int64_t b, int64_t& x, int64_t& y);
uint64_t modinv(uint64_t a, uint64_t mod);                   // extended euclidean
bool     miller_rabin(uint64_t n, int rounds = 10);          // primality
uint64_t generate_prime(int bits);                           // random prime of bit length

#endif