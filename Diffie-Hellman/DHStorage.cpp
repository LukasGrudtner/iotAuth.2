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

void DHStorage::setSessionKey(int _sessionKey)
{
    sessionKey = _sessionKey;
}

void DHStorage::setBase(int _base)
{
    base = _base;
}

void DHStorage::setModulus(int _modulus)
{
    modulus = _modulus;
}

void DHStorage::setExponent(int _exponent)
{
    exponent = _exponent;
}