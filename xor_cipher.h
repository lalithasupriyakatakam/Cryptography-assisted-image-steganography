#pragma once
#include <vector>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
// XOR Encryption
//
//   EncryptedHash = SHA256_Digest XOR ECC_Key   (bit-by-bit)
//
// Decryption is identical (XOR is its own inverse):
//   Digest = EncryptedHash XOR ECC_Key
// ─────────────────────────────────────────────────────────────────────────────

class XORCipher {
public:
    // Encrypt: output[i] = a[i] ^ b[i]
    static std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a,
                                         const std::vector<uint8_t>& b);

    // Decrypt is identical to encrypt (XOR is its own inverse)
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key) {
        return xorBytes(ciphertext, key);
    }
};

// ─── Implementation (inline — simple enough) ─────────────────────────────────
#include <stdexcept>

inline std::vector<uint8_t> XORCipher::xorBytes(const std::vector<uint8_t>& a,
                                                  const std::vector<uint8_t>& b) {
    if (a.size() != b.size())
        throw std::runtime_error("XOR: inputs must be same length");

    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        result[i] = a[i] ^ b[i];
    return result;
}
