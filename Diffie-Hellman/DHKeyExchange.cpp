#include "DHKeyExchange.h"

DHKeyExchange::DHKeyExchange()
{
    memset(encryptedHash, 0, sizeof(encryptedHash));
}

int* DHKeyExchange::getEncryptedHash()
{
    return encryptedHash;
}

DiffieHellmanPackage DHKeyExchange::getDiffieHellmanPackage()
{
    return diffieHellmanPackage;
}

void DHKeyExchange::setEncryptedHash(int encHash[])
{
    for (int i = 0; i < 128; i++) {
        encryptedHash[i] = encHash[i];
    }
}

void DHKeyExchange::setDiffieHellmanPackage(DiffieHellmanPackage dhPackage)
{
    diffieHellmanPackage = dhPackage;
}
