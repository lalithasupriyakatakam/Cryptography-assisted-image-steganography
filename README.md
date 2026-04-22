# Cryptography-assisted-image-steganography

SHA-256 → ECC Key Generation → XOR Encryption → LSB Steganography

A complete end-to-end cryptographic pipeline that hashes a message, generates an ECC-based key, encrypts the hash, and hides the ciphertext inside image pixels using LSB steganography.

</div>
📋 Overview
This project implements a full cryptographic steganography pipeline in pure C++17. It takes a user message, processes it through multiple cryptographic layers, and embeds the result into an image's blue channel LSBs — all without external libraries.

Pipeline Stages
text
User Message → SHA-256 → ECC Key Derivation → XOR Encryption → LSB Embedding → Stego Image
                     ↓                           ↓
               256-bit Hash                Encrypted Hash
Stage	Component	Description
1️⃣	SHA-256	Cryptographic hash of the input message
2️⃣	ECC (mod 5)	Simplified elliptic curve key generation from hash digest
3️⃣	XOR Cipher	Bitwise encryption of hash using ECC-derived key
4️⃣	LSB Steganography	Hide 256 encrypted bits in blue channel LSBs
🔐 Cryptographic Components
SHA-256 Implementation
Pure C++ implementation of the SHA-256 algorithm

Processes messages in 512-bit blocks

Produces 256-bit (32-byte) digest

Round constants and initial hash values per FIPS PUB 180-4

Elliptic Curve Cryptography (Simplified)
Operating over a tiny prime field GF(5) for educational/demonstration purposes:

Parameter	Value
Curve	y² = x³ + 2x + 1 (mod 5)
Generator G	(0, 1)
Scalar k	{1, 2, 3, 4} (derived from hash digest)
ECC Operations:

Point addition (including doubling)

Scalar multiplication (double-and-add algorithm)

Modular arithmetic with custom inverse function

Key Generation Process
text
SHA-256 Digest (32 bytes)
        ↓
Sum all nibbles (64 hex digits)
        ↓
k = (sum % 4) + 1  →  k ∈ {1,2,3,4}
        ↓
Q = k * G  (point multiplication)
        ↓
9-bit pattern: {k[2:0], y[2:0], x[2:0]}
        ↓
Repeat pattern cyclically → 256-bit key
XOR Encryption
Simple but effective bitwise XOR operation

Encryption: Ciphertext = Hash ⊕ ECC_Key

Decryption: Hash = Ciphertext ⊕ ECC_Key

XOR is its own inverse (symmetric)

🖼️ Steganography Module
LSB (Least Significant Bit) Embedding
Hides 256 bits (32 bytes) of encrypted data

Uses blue channel only (imperceptible to human vision)

Modifies only the first 256 pixels of the image

Each pixel stores exactly 1 bit of secret data

Bit Layout
text
Pixel 0 (Blue LSB) → Bit 0 (MSB of byte 0)
Pixel 1 (Blue LSB) → Bit 1
...
Pixel 255 → Bit 255 (LSB of byte 31)
BMP Support
Built-in 24-bit uncompressed BMP reader/writer

Handles BMP padding (4-byte row alignment)

Automatic bottom-to-top conversion

Synthetic test image generation if cover.bmp not found

📁 Project Structure
text
├── main.cpp              # Main pipeline orchestration
├── sha256.h / .cpp       # SHA-256 hash implementation
├── ecc.h / .cpp          # ECC over GF(5) with key generation
├── xor_cipher.h          # XOR encryption (header-only)
├── steganography.h       # LSB embedding/extraction + BMP I/O
└── cover.bmp             # Optional: input cover image
🚀 Getting Started
Prerequisites
C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)

No external dependencies — all implementations are self-contained

Compilation
bash
# Compile all sources
g++ -std=c++17 -O2 main.cpp sha256.cpp ecc.cpp -o stego

# Or with separate compilation
g++ -std=c++17 -c sha256.cpp -o sha256.o
g++ -std=c++17 -c ecc.cpp -o ecc.o
g++ -std=c++17 -c main.cpp -o main.o
g++ main.o sha256.o ecc.o -o stego
Running
bash
./stego
The program will:

Prompt for a message (default: "HELLO")

Display the SHA-256 hash

Show ECC key generation details

Encrypt the hash with XOR

Load/create a cover image

Embed encrypted data into the image

Save stego.bmp with hidden data

Verify extraction and decryption

Expected Output
text
==========================================================
   Cryptography Assisted Image Steganography
   SHA-256 -> ECC Key -> XOR Encrypt -> LSB Embed
==========================================================

Enter message to secure: Hello, World!

STAGE 1: SHA-256 Hash Generation
SHA-256 Hash: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a0be...

STAGE 2: ECC Key Generation
Curve    : y^2 = x^3 + 2x + 1 (mod 5)
Generator: G = (0, 1)
Scalar k: 3
Public key Q = (2, 4)

STAGE 3: XOR Encryption
Encrypted Hash: [c8 f2 41 93 ...]

STAGE 4: LSB Image Steganography
Stego image saved as stego.bmp

Extraction test   : PASS
Hash recovery test: PASS
🔄 Pipeline Verification
The implementation includes automatic verification at each stage:

Check	Description
XOR Decryption	Verifies Decrypt(Encrypt(Hash)) == Hash
Steganography	Verifies extracted bits match embedded data
Hash Recovery	Ensures recovered hash matches original digest
🧮 ECC Mathematics (mod 5)
Curve Points
All points on y² = x³ + 2x + 1 (mod 5):

x	x³+2x+1 (mod5)	y² solutions	Points
0	1	y = ±1	(0,1), (0,4)
1	1+2+1=4	y = ±2	(1,2), (1,3)
2	8+4+1=13≡3	No solution	-
3	27+6+1=34≡4	y = ±2	(3,2), (3,3)
4	64+8+1=73≡3	No solution	-
Scalar Multiplication Results
k	Q = k*G
1	(0, 1)
2	(1, 2)
3	(3, 3)
4	(4, 0)
📊 Technical Specifications
Component	Specification
Hash Algorithm	SHA-256 (FIPS PUB 180-4)
Block Size	512 bits
Digest Size	256 bits
ECC Field	GF(5)
Key Size	256 bits (derived)
Stego Capacity	256 bits (32 bytes)
Channel	Blue (RGB)
Pixel Modification	±1 max (imperceptible)
🎯 Use Cases
Educational: Demonstrates cryptographic primitives in practice

Research Prototype: Testbed for steganographic techniques

Security Awareness: Visualize how data can be hidden in images

Portfolio Project: Full-stack crypto implementation in C++

