#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include "sha256.cpp"


int main() {
	int i = 1;
	while (i)
	{
		std::string i;
		std::string salt;

		std::cout << "Enter any text to encrypt it: ";
		std::getline(std::cin, i);

		std::cout << "Enter salt (optional): ";
		std::getline(std::cin, salt);

		auto out = AES.SHA256(i, salt);

		std::cout << "Hash: " << out << "\n" << std::endl;

	}
	return 0;
}
