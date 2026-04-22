#include "ecc.h"
#include <stdexcept>

// ─── Helpers ──────────────────────────────────────────────────────────────────
int ECC::mod(int a, int m) {
    return ((a % m) + m) % m;   // Always non-negative
}

// Modular inverse using brute-force (fine for small mod like 5)
int ECC::modInverse(int a, int modulus) {
    a = mod(a, modulus);
    for (int i = 1; i < modulus; ++i)
        if (mod(a * i, modulus) == 1)
            return i;
    throw std::runtime_error("Modular inverse does not exist");
}

// ─── Generator Point ──────────────────────────────────────────────────────────
ECPoint ECC::generator() {
    return {0, 1, false};  // P = (0, 1) on y² = x³ + 2x + 1 (mod 5)
}

// ─── Point Addition ───────────────────────────────────────────────────────────
// Handles:
//   • P + ∞ = P  and  ∞ + P = P
//   • P + (-P) = ∞
//   • P + P (doubling)
//   • P + Q (addition)
ECPoint ECC::pointAdd(const ECPoint& P1, const ECPoint& P2) {
    // Identity cases
    if (P1.isInfinity) return P2;
    if (P2.isInfinity) return P1;

    // P + (-P) = point at infinity
    if (P1.x == P2.x && mod(P1.y + P2.y, P) == 0)
        return {0, 0, true};

    int lambda;

    if (P1.x == P2.x && P1.y == P2.y) {
        // Point Doubling: λ = (3x₁² + a) / (2y₁)  mod p
        int numerator   = mod(3 * P1.x * P1.x + A, P);
        int denominator = mod(2 * P1.y, P);
        lambda = mod(numerator * modInverse(denominator, P), P);
    } else {
        // Point Addition: λ = (y₂ - y₁) / (x₂ - x₁)  mod p
        int numerator   = mod(P2.y - P1.y, P);
        int denominator = mod(P2.x - P1.x, P);
        lambda = mod(numerator * modInverse(denominator, P), P);
    }

    // x₃ = λ² - x₁ - x₂  mod p
    int x3 = mod(lambda * lambda - P1.x - P2.x, P);
    // y₃ = λ(x₁ - x₃) - y₁  mod p
    int y3 = mod(lambda * (P1.x - x3) - P1.y, P);

    return {x3, y3, false};
}

// ─── Scalar Multiplication: Q = kP ───────────────────────────────────────────
ECPoint ECC::scalarMultiply(int k) {
    ECPoint result = {0, 0, true};   // Start with point at infinity
    ECPoint addend = generator();    // Start adding from G

    while (k > 0) {
        if (k & 1)                   // If current bit is 1, add current point
            result = pointAdd(result, addend);
        addend = pointAdd(addend, addend);  // Double the point
        k >>= 1;
    }
    return result;
}

// ─── Scalar Derivation from SHA-256 Digest ───────────────────────────────────
// Matches the Verilog k_generator:
//   • Sum all 64 hex nibbles (each byte contributes 2 nibbles)
//   • k = (sum mod 4) + 1  →  k ∈ {1,2,3,4}
int ECC::deriveScalar(const std::vector<uint8_t>& digest) {
    int sum = 0;
    for (uint8_t byte : digest) {
        sum += (byte >> 4) & 0xF;   // High nibble
        sum += (byte     ) & 0xF;   // Low  nibble
    }
    return (sum % 4) + 1;
}

// ─── Key Generation ──────────────────────────────────────────────────────────
// 1. Derive scalar k from digest
// 2. Compute Q = kP
// 3. Pack {k, y, x} into a 9-bit pattern (3 bits each)
// 4. Repeat that pattern cyclically to fill 256 bits
std::vector<uint8_t> ECC::generateKey(const std::vector<uint8_t>& digest) {
    int k = deriveScalar(digest);
    ECPoint Q = scalarMultiply(k);

    // Build 9-bit pattern: {k[2:0], y[2:0], x[2:0]}
    // k, x, y are all small (≤ 4), so 3 bits each is sufficient
    uint16_t pattern9 = ((k & 0x7) << 6) | ((Q.y & 0x7) << 3) | (Q.x & 0x7);

    // Fill 256 bits (32 bytes) by repeating the 9-bit pattern cyclically
    std::vector<uint8_t> key(32, 0);
    for (int bit = 0; bit < 256; ++bit) {
        int patBit = (pattern9 >> (8 - (bit % 9))) & 1;
        if (patBit)
            key[bit / 8] |= (1 << (7 - (bit % 8)));
    }
    return key;
}
