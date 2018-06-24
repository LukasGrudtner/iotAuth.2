#include "DHStorage.h"

int DHStorage::getBase()
{
    return base;
}

int DHStorage::getModulus()
{
    return modulus;
}

int DHStorage::getSessionKey()
{
    return sessionKey;
}

int DHStorage::calculateResult()
{
    int aux = pow(base, exponent);
    return aux % modulus;
}

int DHStorage::calculateSessionKey(int result)
{
    int aux = pow(result, exponent);
    return aux % modulus;
}

void DHStorage::setSessionKey(int sessionKey)
{
    this->sessionKey = sessionKey;
}

void DHStorage::setBase(int base)
{
    this->base = base;
}

void DHStorage::setModulus(int modulus)
{
    this->modulus = modulus;
}

void DHStorage::setExponent(int exponent)
{
    this->exponent = exponent;
}