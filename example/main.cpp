#include <iostream>

#include "../ibdcrypt/ibdcrypt.hpp"

int main() {
    ProtectedUint32 a(100);
    ProtectedUint32 b(25);

    std::cout << "a: " << a.Decrypt() << std::endl;
    std::cout << "b: " << b.Decrypt() << std::endl;

    a -= b;
    std::cout << "a - b = " << a.Decrypt() << std::endl;

    system("pause");
    return 0;
}
