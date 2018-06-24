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

void DHKeyExchange::setEncryptedHash(int encryptedHash[])
{
    for (int i = 0; i < 128; i++) {
        this->encryptedHash[i] = encryptedHash[i];
    }
}

void DHKeyExchange::setDiffieHellmanPackage(DiffieHellmanPackage diffieHellmanPackage)
{
    this->diffieHellmanPackage = diffieHellmanPackage;
}
