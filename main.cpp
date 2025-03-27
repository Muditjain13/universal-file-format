#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <cstring>
#include "UniFileFormat.h"

// Compute SHA-256 checksum for data integrity
std::vector<uint8_t> computeSHA256(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    SHA256_Final(hash, &sha256_ctx);
    return std::vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH);
}

// Encrypt data using AES-256
std::vector<uint8_t> aes256Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    AES_KEY encryptKey;
    AES_set_encrypt_key(key.data(), 256, &encryptKey);

    std::vector<uint8_t> encryptedData(data.size());
    AES_encrypt(data.data(), encryptedData.data(), &encryptKey);
    return encryptedData;
}

// Decrypt data using AES-256
std::vector<uint8_t> aes256Decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    AES_KEY decryptKey;
    AES_set_decrypt_key(key.data(), 256, &decryptKey);

    std::vector<uint8_t> decryptedData(data.size());
    AES_decrypt(data.data(), decryptedData.data(), &decryptKey);
    return decryptedData;
}

// Compress data using zlib (lossless compression)
std::vector<uint8_t> compressData(const std::vector<uint8_t>& data) {
    uLongf compressedSize = compressBound(data.size());
    std::vector<uint8_t> compressedData(compressedSize);

    int ret = compress(compressedData.data(), &compressedSize, data.data(), data.size());
    if (ret != Z_OK) {
        throw std::runtime_error("Compression failed");
    }

    compressedData.resize(compressedSize);
    return compressedData;
}

// Decompress data using zlib (lossless decompression)
std::vector<uint8_t> decompressData(const std::vector<uint8_t>& data) {
    uLongf decompressedSize = data.size() * 10;  // Estimate decompressed size (can adjust as needed)
    std::vector<uint8_t> decompressedData(decompressedSize);

    int ret = uncompress(decompressedData.data(), &decompressedSize, data.data(), data.size());
    if (ret != Z_OK) {
        throw std::runtime_error("Decompression failed");
    }

    decompressedData.resize(decompressedSize);  // Trim to actual size
    return decompressedData;
}

// Write a .uni file (image or video)
void writeUniFile(const std::string& filePath, const std::vector<uint8_t>& data, bool isImage, bool compress, bool encrypt, const std::vector<uint8_t>& encryptionKey) {
    // Create a UniHeader
    UniHeader header;
    std::memcpy(header.magic, "UNI", 3);
    header.version = 1;
    header.contentType = isImage ? 1 : 2;  // 1 for image, 2 for video
    header.compressionType = compress ? 1 : 0; // Compression type (lossless or none)
    header.encryptionType = encrypt ? 1 : 0;  // Encryption type (AES-256 or none)

    // Compress the data if needed
    std::vector<uint8_t> finalData = data;
    if (compress) {
        finalData = compressData(data);
    }

    // Encrypt the data if needed
    if (encrypt) {
        finalData = aes256Encrypt(finalData, encryptionKey);
    }

    // Calculate the size of the data
    header.dataSize = finalData.size();

    // Calculate the checksum (SHA-256)
    std::vector<uint8_t> checksum = computeSHA256(finalData);
    header.checksumSize = checksum.size();

    // Write the file
    std::ofstream outFile(filePath, std::ios::binary);

    // Write header
    outFile.write(reinterpret_cast<const char*>(&header), sizeof(header));

    // Write the data segment
    outFile.write(reinterpret_cast<const char*>(finalData.data()), finalData.size());

    // Write the checksum
    outFile.write(reinterpret_cast<const char*>(checksum.data()), checksum.size());

    outFile.close();
}

// Read a .uni file and verify checksum
void readUniFile(const std::string& filePath) {
    std::ifstream inFile(filePath, std::ios::binary);

    // Read the header
    UniHeader header;
    inFile.read(reinterpret_cast<char*>(&header), sizeof(header));

    // Validate magic number
    if (std::memcmp(header.magic, "UNI", 3) != 0) {
        std::cerr << "Not a valid UNI file." << std::endl;
        return;
    }

    // Read the data segment
    std::vector<uint8_t> data(header.dataSize);
    inFile.read(reinterpret_cast<char*>(data.data()), header.dataSize);

    // Read the checksum
    std::vector<uint8_t> checksum(header.checksumSize);
    inFile.read(reinterpret_cast<char*>(checksum.data()), header.checksumSize);

    // Verify checksum
    if (computeSHA256(data) != checksum) {
        std::cerr << "Checksum verification failed." << std::endl;
        return;
    }

    // Decrypt the data if it's encrypted
    if (header.encryptionType == 1) {
        data = aes256Decrypt(data, { 't', 'h', 'i', 's', 'i', 's', 'a', 'n', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'k' });  // Example AES key
    }

    // Decompress the data if it's compressed
    if (header.compressionType == 1) {
        data = decompressData(data);
    }

    // Now you have the data and can process it (image/video)
    std::cout << "File read successfully!" << std::endl;
}

int main() {
    // Example usage
    std::vector<uint8_t> data = { 'T', 'e', 's', 't', ' ', 'D', 'a', 't', 'a' }; // Example data
    std::vector<uint8_t> encryptionKey = { 't', 'h', 'i', 's', 'i', 's', 'a', 'n', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'k' }; // Example AES key

    // Writing .uni file
    writeUniFile("example.uni", data, true, false, true, encryptionKey);
    std::cout << "UNI file created successfully!" << std::endl;

    // Reading .uni file
    readUniFile("example.uni");

    return 0;
}
