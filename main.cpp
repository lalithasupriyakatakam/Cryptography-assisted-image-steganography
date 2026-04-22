#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>
#include <bitset>

#include "sha256.h"
#include "ecc.h"
#include "xor_cipher.h"
#include "steganography.h"

void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (uint8_t b : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << "\n";
}

Image createTestImage(int width = 64, int height = 64) {
    Image img;
    img.width  = width;
    img.height = height;
    img.pixels.resize(width * height * 3);
    for (int y = 0; y < height; ++y)
        for (int x = 0; x < width; ++x) {
            img.pixels[(y * width + x) * 3 + 0] = (uint8_t)(x * 4);
            img.pixels[(y * width + x) * 3 + 1] = (uint8_t)(y * 4);
            img.pixels[(y * width + x) * 3 + 2] = (uint8_t)(128);
        }
    return img;
}

int main() {
    std::cout << "==========================================================\n";
    std::cout << "   Cryptography Assisted Image Steganography\n";
    std::cout << "   SHA-256 -> ECC Key -> XOR Encrypt -> LSB Embed\n";
    std::cout << "==========================================================\n\n";

    std::string message;
    std::cout << "Enter message to secure (or press Enter for 'HELLO'): ";
    std::getline(std::cin, message);
    if (message.empty()) message = "HELLO";

    std::cout << "\n----------------------------------------------------------\n";
    std::cout << "Message : \"" << message << "\"\n";
    std::cout << "Length  : " << message.size() << " bytes = "
              << message.size() * 8 << " bits\n";

    // STAGE 1
    std::cout << "\n----------------------------------------------------------\n";
    std::cout << "STAGE 1: SHA-256 Hash Generation\n";
    std::cout << "----------------------------------------------------------\n";

    std::vector<uint8_t> digest = SHA256::hashBytes(message);
    std::string hashHex         = SHA256::hash(message);

    std::cout << "SHA-256 Hash (hex):\n  " << hashHex << "\n";
    std::cout << "Hash size: " << digest.size() * 8 << " bits  --> OK\n";

    // STAGE 2
    std::cout << "\n----------------------------------------------------------\n";
    std::cout << "STAGE 2: ECC Key Generation (mod-5 simplified curve)\n";
    std::cout << "----------------------------------------------------------\n";
    std::cout << "Curve    : y^2 = x^3 + 2x + 1  (mod 5)\n";
    std::cout << "Generator: G = (0, 1)\n";

    int k       = ECC::deriveScalar(digest);
    ECPoint Q   = ECC::scalarMultiply(k);
    auto eccKey = ECC::generateKey(digest);

    std::cout << "Scalar k derived from digest : " << k << "\n";
    std::cout << "Public key Q = k*G = (" << Q.x << ", " << Q.y << ")\n";
    std::cout << "9-bit pattern {k, y, x}      : "
              << std::bitset<3>(k) << " "
              << std::bitset<3>(Q.y) << " "
              << std::bitset<3>(Q.x) << "\n";
    printHex("ECC Key (256-bit)", eccKey);

    // STAGE 3
    std::cout << "\n----------------------------------------------------------\n";
    std::cout << "STAGE 3: XOR Encryption  (Digest XOR ECC Key)\n";
    std::cout << "----------------------------------------------------------\n";

    auto encryptedHash = XORCipher::xorBytes(digest, eccKey);

    printHex("SHA-256 Digest ", digest);
    printHex("ECC Key        ", eccKey);
    printHex("Encrypted Hash ", encryptedHash);

    auto decrypted = XORCipher::decrypt(encryptedHash, eccKey);
    bool decryptOK = (decrypted == digest);
    std::cout << "Decryption test: " << (decryptOK ? "PASS" : "FAIL") << "\n";

    // STAGE 4
    std::cout << "\n----------------------------------------------------------\n";
    std::cout << "STAGE 4: LSB Image Steganography\n";
    std::cout << "----------------------------------------------------------\n";

    Image cover;
    try {
        cover = loadBMP("cover.bmp");
        std::cout << "Loaded cover.bmp ("
                  << cover.width << "x" << cover.height << " pixels)\n";
    } catch (...) {
        std::cout << "cover.bmp not found - generating synthetic 64x64 test image\n";
        cover = createTestImage(64, 64);
        saveBMP("cover.bmp", cover);
        std::cout << "Saved synthetic cover.bmp\n";
    }

    Image stego = Steganography::embed(cover, encryptedHash);
    saveBMP("stego.bmp", stego);
    std::cout << "Stego image saved as stego.bmp\n";

    std::cout << "\n--- Pixel Comparison (Blue channel, first 16 pixels) ---\n";
    std::cout << "Pixel | Cover B | Stego B | Changed?\n";
    std::cout << "------+---------+---------+---------\n";
    for (int i = 0; i < 16; ++i) {
        uint8_t cb = cover.pixels[i * 3 + 2];
        uint8_t sb = stego.pixels[i * 3 + 2];
        std::cout << "  " << std::setw(3) << i
                  << "  |   " << std::setw(3) << (int)cb
                  << "   |   " << std::setw(3) << (int)sb
                  << "   | " << (cb != sb ? "YES (+1)" : "no") << "\n";
    }

    auto extracted     = Steganography::extract(stego);
    bool stegoOK       = (extracted == encryptedHash);
    auto recoveredHash = XORCipher::decrypt(extracted, eccKey);
    bool hashOK        = (recoveredHash == digest);

    std::cout << "\nExtraction test   : " << (stegoOK ? "PASS" : "FAIL") << "\n";
    std::cout << "Hash recovery test: " << (hashOK  ? "PASS" : "FAIL") << "\n";

    std::cout << "\n==========================================================\n";
    std::cout << "PIPELINE SUMMARY\n";
    std::cout << "==========================================================\n";
    std::cout << "  Input Message  : \"" << message << "\"\n";
    std::cout << "  SHA-256 Hash   : " << hashHex.substr(0, 32) << "...\n";
    std::cout << "  ECC Scalar k   : " << k
              << "  |  Q = (" << Q.x << "," << Q.y << ")\n";
    std::cout << "  Encrypted bits : hidden in blue LSBs of stego.bmp\n";
    std::cout << "  Max pixel diff : 1 (imperceptible to human eye)\n";
    std::cout << "==========================================================\n";

    return 0;
}
