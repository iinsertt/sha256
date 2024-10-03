#include <array>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
constexpr std::array<uint32_t, 64> k = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};




extern class AES
{
private:
static std::vector<uint8_t> init_sha256(const std::vector<uint8_t>& input) {
	std::vector<uint8_t> message(input);
	message.push_back(0x80);
	while ((message.size() + 8) % 64 != 0) {
		message.push_back(0x00);
	}
	const uint64_t original_length = input.size() * 8;
	message.push_back(static_cast<uint8_t>(original_length >> 56));
	message.push_back(static_cast<uint8_t>(original_length >> 48));
	message.push_back(static_cast<uint8_t>(original_length >> 40));
	message.push_back(static_cast<uint8_t>(original_length >> 32));
	message.push_back(static_cast<uint8_t>(original_length >> 24));
	message.push_back(static_cast<uint8_t>(original_length >> 16));
	message.push_back(static_cast<uint8_t>(original_length >> 8));
	message.push_back(static_cast<uint8_t>(original_length));

	std::array<uint32_t, 8> h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	for (size_t i = 0; i < message.size(); i += 64) {
		std::array<uint32_t, 64> w;
		std::memcpy(w.data(), message.data() + i, 64);
		for (size_t j = 16; j < 64; ++j) {
			const uint32_t s0 = ((w[j - 15] >> 7) | (w[j - 15] << 25)) ^ ((w[j - 15] >> 18) | (w[j - 15] << 14)) ^ (w[j - 15] >> 3);
			const uint32_t s1 = ((w[j - 2] >> 17) | (w[j - 2] << 15)) ^ ((w[j - 2] >> 19) | (w[j - 2] << 13)) ^ (w[j - 2] >> 10);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}

		std::array<uint32_t, 8> a = h;
		for (size_t j = 0; j < 64; ++j) {
			const uint32_t s1 = ((a[4] >> 6) | (a[4] << 26)) ^ ((a[4] >> 11) | (a[4] << 21)) ^ ((a[4] >> 25) | (a[4] << 7));
			const uint32_t ch = (a[4] & a[5]) ^ (~a[4] & a[6]);
			const uint32_t temp1 = a[7] + s1 + ch + k[j] + w[j];
			const uint32_t s0 = ((a[0] >> 2) | (a[0] << 30)) ^ ((a[0] >> 13) | (a[0] << 19)) ^ ((a[0] >> 22) | (a[0] << 10));
			const uint32_t maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
			const uint32_t temp2 = s0 + maj;

			a[7] = a[6];
			a[6] = a[5];
			a[5] = a[4];
			a[4] = a[3] + temp1;
			a[3] = a[2];
			a[2] = a[1];
			a[1] = a[0];
			a[0] = temp1 + temp2;
		}

		for (size_t j = 0; j < 8; ++j) {
			h[j] += a[j];
		}
	}

	std::vector<uint8_t> digest(32);
	for (size_t i = 0; i < 8; ++i) {
		digest[i * 4 + 0] = static_cast<uint8_t>(h[i] >> 24);

		digest[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
		digest[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
		digest[i * 4 + 3] = static_cast<uint8_t>(h[i]);
	}
	return digest;
}
public:
static std::string SHA256(std::string i, std::string salt = "salt") {
	i += salt;
	std::vector<uint8_t> input = {};
	for (const auto elem : i) {
		input.push_back(elem);
	}
	std::vector<uint8_t> digest = init_sha256(input);
	std::stringstream out;
	for (uint8_t byte : digest) {
		out << std::hex << static_cast<int>(byte);
	}
	return out.str();
}
} AES;