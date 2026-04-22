#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <iostream>

// ─────────────────────────────────────────────────────────────────────────────
// LSB Image Steganography
//
// Works on a simple raw pixel buffer (RGB, 3 bytes per pixel).
// Hides 256 encrypted bits in the BLUE channel (channel index 2)
// of the first 256 pixels — matching the MATLAB implementation.
//
// Since C++ has no built-in PNG/BMP support, we provide:
//   • A BMP reader/writer (no external library needed)
//   • embed() — hide bits in blue channel LSBs
//   • extract() — recover bits from blue channel LSBs
// ─────────────────────────────────────────────────────────────────────────────

// Simple image structure: flat RGB byte array + dimensions
struct Image {
    int width = 0, height = 0;
    std::vector<uint8_t> pixels; // size = width * height * 3  (R,G,B order)

    uint8_t& r(int row, int col) { return pixels[(row * width + col) * 3 + 0]; }
    uint8_t& g(int row, int col) { return pixels[(row * width + col) * 3 + 1]; }
    uint8_t& b(int row, int col) { return pixels[(row * width + col) * 3 + 2]; }
};

// ─── BMP I/O ─────────────────────────────────────────────────────────────────
// Reads a 24-bit uncompressed BMP file into an Image struct
inline Image loadBMP(const std::string& filename) {
    std::ifstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file: " + filename);

    uint8_t header[54];
    f.read(reinterpret_cast<char*>(header), 54);

    int width  = *reinterpret_cast<int*>(&header[18]);
    int height = *reinterpret_cast<int*>(&header[22]);
    int offset = *reinterpret_cast<int*>(&header[10]);

    f.seekg(offset);

    // BMP rows are stored bottom-to-top and padded to 4-byte boundaries
    int rowSize = ((width * 3 + 3) / 4) * 4;

    Image img;
    img.width  = width;
    img.height = (height < 0) ? -height : height;  // handle negative height
    img.pixels.resize(img.width * img.height * 3);

    std::vector<uint8_t> row(rowSize);
    for (int y = img.height - 1; y >= 0; --y) {   // BMP = bottom-up
        f.read(reinterpret_cast<char*>(row.data()), rowSize);
        for (int x = 0; x < img.width; ++x) {
            img.pixels[(y * img.width + x) * 3 + 0] = row[x * 3 + 2]; // R
            img.pixels[(y * img.width + x) * 3 + 1] = row[x * 3 + 1]; // G
            img.pixels[(y * img.width + x) * 3 + 2] = row[x * 3 + 0]; // B
        }
    }
    return img;
}

// Writes Image struct to a 24-bit uncompressed BMP file
inline void saveBMP(const std::string& filename, const Image& img) {
    std::ofstream f(filename, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write file: " + filename);

    int rowSize = ((img.width * 3 + 3) / 4) * 4;
    int dataSize = rowSize * img.height;
    int fileSize = 54 + dataSize;

    // BMP file header (14 bytes)
    uint8_t header[54] = {};
    header[0] = 'B'; header[1] = 'M';
    *reinterpret_cast<int*>(&header[2])  = fileSize;
    *reinterpret_cast<int*>(&header[10]) = 54;         // pixel data offset
    // DIB header (40 bytes)
    *reinterpret_cast<int*>(&header[14]) = 40;         // DIB header size
    *reinterpret_cast<int*>(&header[18]) = img.width;
    *reinterpret_cast<int*>(&header[22]) = -img.height; // negative = top-down
    *reinterpret_cast<uint16_t*>(&header[26]) = 1;    // color planes
    *reinterpret_cast<uint16_t*>(&header[28]) = 24;   // bits per pixel
    *reinterpret_cast<int*>(&header[34]) = dataSize;

    f.write(reinterpret_cast<char*>(header), 54);

    std::vector<uint8_t> row(rowSize, 0);
    for (int y = 0; y < img.height; ++y) {
        for (int x = 0; x < img.width; ++x) {
            row[x * 3 + 2] = img.pixels[(y * img.width + x) * 3 + 0]; // R
            row[x * 3 + 1] = img.pixels[(y * img.width + x) * 3 + 1]; // G
            row[x * 3 + 0] = img.pixels[(y * img.width + x) * 3 + 2]; // B
        }
        f.write(reinterpret_cast<char*>(row.data()), rowSize);
    }
}

// ─── Steganography ───────────────────────────────────────────────────────────
class Steganography {
public:
    // Embed 256 bits (32 bytes) into blue channel LSBs of first 256 pixels
    static Image embed(const Image& cover, const std::vector<uint8_t>& data256bits);

    // Extract 256 bits from blue channel LSBs of first 256 pixels
    static std::vector<uint8_t> extract(const Image& stego);

    // Print pixel comparison (cover vs stego) for the first N pixels
    static void comparePixels(const Image& cover, const Image& stego, int count = 16);
};

// ─── Implementation ──────────────────────────────────────────────────────────
inline Image Steganography::embed(const Image& cover,
                                   const std::vector<uint8_t>& data256bits) {
    if (data256bits.size() != 32)
        throw std::runtime_error("embed() expects exactly 32 bytes (256 bits)");
    if (cover.width * cover.height < 256)
        throw std::runtime_error("Image too small: need at least 256 pixels");

    Image stego = cover;  // Copy the cover image

    for (int bit = 0; bit < 256; ++bit) {
        int byteIndex = bit / 8;
        int bitIndex  = 7 - (bit % 8);  // MSB first
        int bitValue  = (data256bits[byteIndex] >> bitIndex) & 1;

        // Modify the LSB of the blue channel of pixel[bit]
        // pixel index = bit (we use the first 256 pixels, row by row)
        int pixelOffset = bit * 3 + 2;  // +2 = blue channel
        stego.pixels[pixelOffset] = (stego.pixels[pixelOffset] & 0xFE) | bitValue;
    }
    return stego;
}

inline std::vector<uint8_t> Steganography::extract(const Image& stego) {
    std::vector<uint8_t> data(32, 0);

    for (int bit = 0; bit < 256; ++bit) {
        int pixelOffset = bit * 3 + 2;  // blue channel of pixel[bit]
        int bitValue    = stego.pixels[pixelOffset] & 1;

        int byteIndex = bit / 8;
        int bitIndex  = 7 - (bit % 8);
        if (bitValue)
            data[byteIndex] |= (1 << bitIndex);
    }
    return data;
}

inline void Steganography::comparePixels(const Image& cover,
                                          const Image& stego, int count) {
    std::cout << "\n--- Pixel Comparison (Blue channel, first "
              << count << " pixels) ---\n";
    std::cout << "Pixel  | Cover B | Stego B | Changed?\n";
    std::cout << "-------+---------+---------+---------\n";

    for (int i = 0; i < count && i < cover.width * cover.height; ++i) {
        uint8_t cb = cover.pixels[i * 3 + 2];
        uint8_t sb = stego.pixels[i * 3 + 2];
        std::cout << "  " << std::setw(3) << i
                  << "  |   " << std::setw(3) << (int)cb
                  << "   |   " << std::setw(3) << (int)sb
                  << "   | " << (cb != sb ? "YES (+1)" : "no") << "\n";
    }
}

// For std::setw in the inline function above
#include <iomanip>
