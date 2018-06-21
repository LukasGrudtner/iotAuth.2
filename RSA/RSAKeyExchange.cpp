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

void RSAKeyExchange::setRSAPackage(RSAPackage *rsaP)
{
    rsaPackage = *rsaP;
}

void RSAKeyExchange::setEncryptedHash(int encHash[])
{
    for (int i = 0; i < 128; i++) {
        encryptedHash[i] = encHash[i];
    }
}

void RSAKeyExchange::setProcessingTime(double processingTime)
{
    tp = processingTime;
}