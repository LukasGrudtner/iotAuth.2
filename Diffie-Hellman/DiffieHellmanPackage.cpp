#include "DiffieHellmanPackage.h"
#include <iostream>

int DiffieHellmanPackage::getResult()
{
    return result;
}

int DiffieHellmanPackage::getBase()
{
    return g;
}

int DiffieHellmanPackage::getModulus()
{
    return p;
}

string DiffieHellmanPackage::getNonceA()
{
    string nonce (nonceA);
    return nonce;
}

string DiffieHellmanPackage::getNonceB()
{
    string nonce (nonceB);
    return nonceB;
}

void DiffieHellmanPackage::setNonceA(char *nonce)
{
    strncpy(nonceA, nonce, sizeof(nonceA));
}

void DiffieHellmanPackage::setNonceB(char *nonce)
{
    strncpy(nonceB, nonce, sizeof(nonceB));
}

void DiffieHellmanPackage::setResult(int r)
{
    result = r;
}

void DiffieHellmanPackage::setBase(int base)
{
    g = base;
}

void DiffieHellmanPackage::setModulus(int modulus)
{
    p = modulus;
}

std::string DiffieHellmanPackage::toString()
{
    std::string result =    std::to_string(getResult())     + ":" +
                            std::to_string(getBase())       + ":" +
                            std::to_string(getModulus());

    return result;
}
