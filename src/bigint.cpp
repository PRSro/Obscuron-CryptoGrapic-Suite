#include "../includes/bigint.hpp"

// lessons learned: this to access the current element, friend to access private functions
void BigInt::trim() {
    while (limbs.size() > 1 && limbs.back() == 0)
        limbs.pop_back();
}

int BigInt::compare(const BigInt& other) const {
    if (limbs.size()!=other.limbs.size())
        return limbs.size()>other.limbs.size()?1:-1;
    int n=limbs.size();
    for (int i=n-1; i>=0; i--) {
        if (limbs[i]!=other.limbs[i])
            return limbs[i]>other.limbs[i]?1:-1;
    }
    return 0;
}
// COMPARISON
bool BigInt::operator==(const BigInt& other) const {
    return negative == other.negative && compare(other) == 0;
}
bool BigInt::operator!=(const BigInt& other) const {return !(*this==other);}
bool BigInt::operator<(const BigInt& other) const {
    if (negative!=other.negative) return negative;
    return negative?compare(other)>0:compare(other)<0;
}
bool BigInt::operator> (const BigInt& other) const { return other<*this; }
bool BigInt::operator<=(const BigInt& other) const { return !(other<*this); }
bool BigInt::operator>=(const BigInt& other) const { return !(*this<other); }
// MAGNITUDE
BigInt BigInt::add_magnitudes(const BigInt& other) const {
    std::vector<uint32_t> result;
    uint64_t carry = 0;
    size_t n = std::max(limbs.size(), other.limbs.size());
    for (size_t i = 0; i < n || carry; i++) {
        uint64_t sum = carry;
        if (i < limbs.size()) sum+=limbs[i];
        if (i < other.limbs.size()) sum+=other.limbs[i];
        result.push_back((uint32_t)(sum&0xFFFFFFFF));
        carry = sum >> 32;
    }
    return BigInt(false, result);
}

BigInt BigInt::sub_magnitudes(const BigInt& other) const {
    std::vector<uint32_t> result;
    int64_t borrow=0;
    size_t n=limbs.size();
    for (size_t i=0; i<n; i++) {
        int64_t diff = (int64_t)limbs[i]-borrow-(i<other.limbs.size()?other.limbs[i]:0);
        if (diff < 0) { diff += (1LL << 32); borrow = 1; }
        else borrow = 0;
        result.push_back((uint32_t)diff);
    }
    BigInt r(false, result);
    r.trim();
    return r;
}
// ARITHMETIC OPERATOR
BigInt BigInt::operator+(const BigInt& other) const {
    if (negative == other.negative) {
        BigInt r = add_magnitudes(other);
        r.negative = negative;
        return r;
    }
    int cmp=compare(other);
    if (cmp==0) return BigInt(0ULL);
    if (cmp>0) {
        BigInt r=sub_magnitudes(other);
        r.negative=negative;
        return r;
    }
    BigInt r=other.sub_magnitudes(*this);
    r.negative=other.negative;
    return r;
}

BigInt BigInt::operator-(const BigInt& other) const {
    BigInt neg_other=other;
    neg_other.negative=!other.negative;
    return *this+neg_other;
}

BigInt BigInt::operator*(const BigInt& other) const {
    std::vector<uint32_t> result(limbs.size() + other.limbs.size(), 0);
    for (size_t i = 0; i < limbs.size(); i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < other.limbs.size() || carry; j++) {
            uint64_t cur=result[i+j];
            uint64_t mul=(j<other.limbs.size())?(uint64_t)limbs[i]*other.limbs[j]:0;
            cur+=mul+carry;
            result[i+j]=(uint32_t)(cur&0xFFFFFFFF);
            carry=cur>>32;
        }
    }
    BigInt r(negative != other.negative, result);
    r.trim();
    return r;
}

BigInt BigInt::operator/(const BigInt& other) const {
    if (other == BigInt(0ULL)) return BigInt(0ULL);
    BigInt abs_this  = *this; abs_this.negative =false;
    BigInt abs_other = other; abs_other.negative=false;
    int cmp = abs_this.compare(abs_other);
    if (cmp < 0) return BigInt(0ULL);
    if (cmp == 0) {
        BigInt one(1ULL);
        one.negative = (negative != other.negative);
        return one;
    }
    BigInt l(0ULL);
    BigInt h = abs_this;
    BigInt q(0ULL);
    while (l <= h) {
        BigInt m=l+h;
        int n = m.limbs.size();
        std::vector<uint32_t> half(n);
        uint32_t rem = 0;
        for (int i = n-1; i >= 0; i--) {
            half[i] = (m.limbs[i] >> 1) | (rem << 31);
            rem     =  m.limbs[i] & 1;
        }
        BigInt mv(false, half);
        mv.trim();
        BigInt prod = mv * abs_other;
        if (prod == abs_this) { q = mv; break; }
        else if (prod < abs_this) { q = mv; l = mv + BigInt(1ULL); }
        else h = mv - BigInt(1ULL);
    }
    q.negative = (negative != other.negative);
    q.trim();
    return q;
}

BigInt BigInt::operator%(const BigInt& other) const {
    BigInt q=*this/other;
    BigInt abs_other=other; abs_other.negative=false;
    BigInt r=*this-q*other;
    r.negative=false;
    r.trim();
    return r;
}

std::ostream& operator<<(std::ostream& os, const BigInt& n) {
    os << n.toString();
    return os;
}