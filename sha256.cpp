#include "sha256.h"
#include <sstream>
#include <iomanip>
#include <cstdint>

#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

const uint32_t k[] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t Sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t Sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

std::string sha256(const std::string& msg) {
    uint32_t h[8];
    uint32_t w[64];

    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;

    uint64_t len = msg.length() * 8;

    std::string paddedMsg = msg;
    paddedMsg += (char)0x80;
    while ((paddedMsg.length() + 8) % 64 != 0)
        paddedMsg += (char)0x00;

    paddedMsg += (char)(len >> 56);
    paddedMsg += (char)(len >> 48);
    paddedMsg += (char)(len >> 40);
    paddedMsg += (char)(len >> 32);
    paddedMsg += (char)(len >> 24);
    paddedMsg += (char)(len >> 16);
    paddedMsg += (char)(len >> 8);
    paddedMsg += (char)(len);

    for (size_t i = 0; i < paddedMsg.length(); i += 64) {
        for (int t = 0; t < 16; t++) {
            w[t] = (uint32_t)paddedMsg[i + t * 4 + 0] << 24;
            w[t] |= (uint32_t)paddedMsg[i + t * 4 + 1] << 16;
            w[t] |= (uint32_t)paddedMsg[i + t * 4 + 2] << 8;
            w[t] |= (uint32_t)paddedMsg[i + t * 4 + 3];
        }

        for (int t = 16; t < 64; t++) {
            w[t] = sigma1(w[t - 2]) + w[t - 7] + sigma0(w[t - 15]) + w[t - 16];
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int t = 0; t < 64; t++) {
            uint32_t t1 = hh + Sigma1(e) + Ch(e, f, g) + k[t] + w[t];
            uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    std::stringstream ss;
    for (int i = 0; i < 8; i++) {
        ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    }

    return ss.str();
}
