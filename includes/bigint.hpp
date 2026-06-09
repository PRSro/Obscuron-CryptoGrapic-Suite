#include <vector>
#include <cstdint>
#include <string>

class BigInt {
public:
    std::vector<uint32_t> limbs; // base 2^32, LE
    bool negative;
    BigInt():negative(false) { limbs.push_back(0); }
    BigInt(uint64_t val):negative(false) {
        if (val==0) {limbs.push_back(0); return;}
        while (val>0) {
            limbs.push_back((uint32_t)(val&0xFFFFFFFF));
            val>>=32;
        }
    }
    BigInt(bool neg, std::vector<uint32_t> l) : negative(neg), limbs(l) {}
    BigInt(const std::string& str);
    BigInt operator+(const BigInt& other) const;
    BigInt operator-(const BigInt& other) const;
    BigInt operator*(const BigInt& other) const;
    BigInt operator/(const BigInt& other) const;
    BigInt operator%(const BigInt& other) const;
    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;
    bool operator< (const BigInt& other) const;
    bool operator> (const BigInt& other) const;
    bool operator<=(const BigInt& other) const;
    bool operator>=(const BigInt& other) const;
    std::string toString() const;
    friend std::ostream& operator<<(std::ostream& os, const BigInt& n);
private:
    void trim();
    int  compare(const BigInt& other) const;
    BigInt add_magnitudes(const BigInt& other) const;
    BigInt sub_magnitudes(const BigInt& other) const; // assumes |this| >= |other|
};


