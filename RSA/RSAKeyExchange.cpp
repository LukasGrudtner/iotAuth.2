#include "RSAKeyExchange.h"

RSAPackage *RSAKeyExchange::getRSAPackage()
{
    return &rsaPackage;
}

int *RSAKeyExchange::getEncryptedHash()
{
    return encryptedHash;
}

double RSAKeyExchange::getProcessingTime()
{
    return tp;
}

void RSAKeyExchange::setRSAPackage(RSAPackage *rsaPackage)
{
    this->rsaPackage = *rsaPackage;
}

void RSAKeyExchange::setEncryptedHash(int encryptedHash[])
{
    for (int i = 0; i < 128; i++) {
        this->encryptedHash[i] = encryptedHash[i];
    }
}

void RSAKeyExchange::setProcessingTime(double tp)
{
    this->tp = tp;
}