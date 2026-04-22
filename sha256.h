#pragma once
#include <string>
#include <vector>
#include <cstdint>

class SHA256 {
public:
    // Returns 256-bit hash as 64-char hex string
    static std::string hash(const std::string& message);

    // Returns raw 32-byte digest
    static std::vector<uint8_t> hashBytes(const std::string& message);

private:
    // Initial hash values (fractional parts of sqrt of first 8 primes)
    static const uint32_t H0[8];

    // Round constants (fractional parts of cbrt of first 64 primes)
    static const uint32_t K[64];

    // Bitwise operations
    static uint32_t rotr(uint32_t x, uint32_t n);
    static uint32_t shr(uint32_t x, uint32_t n);

    // SHA-256 functions
    static uint32_t sigma0(uint32_t x);   // lowercase σ0
    static uint32_t sigma1(uint32_t x);   // lowercase σ1
    static uint32_t Sigma0(uint32_t x);   // uppercase Σ0
    static uint32_t Sigma1(uint32_t x);   // uppercase Σ1
    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

    // Core processing
    static std::vector<uint8_t> preprocess(const std::string& message);
    static void processBlock(const uint8_t* block, uint32_t hash[8]);
};
