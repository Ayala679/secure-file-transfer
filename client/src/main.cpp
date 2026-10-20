#include <cryptopp/cryptlib.h>

#include <iostream>

int main()
{
    std::cout << "client version 3, CryptoPP " << CryptoPP::LibraryVersion() << '\n';
    return 0;
}
