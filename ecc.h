#pragma once
#include <vector>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
// Simplified ECC over GF(5)  — matches the Verilog design in the project
//
// Curve : y² ≡ x³ + 2x + 1  (mod 5)
// Generator point P = (0, 1)
// Scalar k ∈ {1, 2, 3, 4}  (derived from SHA-256 digest)
// ─────────────────────────────────────────────────────────────────────────────

struct ECPoint {
    int x, y;
    bool isInfinity = false; // Point at infinity (identity element)
};

class ECC {
public:
    // Derive 256-bit key from SHA-256 digest bytes
    static std::vector<uint8_t> generateKey(const std::vector<uint8_t>& digest);

    // Expose scalar derivation (for display/debug)
    static int deriveScalar(const std::vector<uint8_t>& digest);

    // Expose point multiplication (for display/debug)
    static ECPoint scalarMultiply(int k);

private:
    static const int P = 5;  // Prime field modulus
    static const int A = 2;  // Curve coefficient a
    // Curve: y² = x³ + 2x + 1 (mod 5)

    static ECPoint generator();
    static ECPoint pointAdd(const ECPoint& P1, const ECPoint& P2);
    static int modInverse(int a, int mod);
    static int mod(int a, int m);
};
