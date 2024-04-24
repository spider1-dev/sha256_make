#include <iostream>
#include <string>
#include "sha256.h"

int main() {
    std::string input = "Merhaba, dünya!";
    std::string hashed = sha256(input);
    std::cout << "Girdi: " << input << std::endl;
    std::cout << "SHA-256: " << hashed << std::endl;
    return 0;
}
