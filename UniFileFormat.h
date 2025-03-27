#pragma once
#include <vector>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <zlib.h>

// Header structure for .uni file
struct UniHeader {
    char magic[3];          // Magic number ("UNI")
    uint8_t version;        // File version
    uint8_t contentType;    // 1 for image, 2 for video
    uint8_t compressionType; // 0 = None, 1 = Lossless, 2 = Lossy
    uint8_t encryptionType;  // 0 = None, 1 = AES-256
    uint32_t dataSize;      // Size of data segment (in bytes)
    uint32_t checksumSize;  // Size of checksum (SHA-256)
};

// Function declarations
std::vector<uint8_t> computeSHA256(const std::vector<uint8_t>& data);
std::vector<uint8_t> aes256Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
std::vector<uint8_t> aes256Decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);  // AES Decryption
std::vector<uint8_t> compressData(const std::vector<uint8_t>& data);
std::vector<uint8_t> decompressData(const std::vector<uint8_t>& data);  // Zlib Decompression
void writeUniFile(const std::string& filePath, const std::vector<uint8_t>& data, bool isImage, bool compress, bool encrypt, const std::vector<uint8_t>& encryptionKey);
void readUniFile(const std::string& filePath);
