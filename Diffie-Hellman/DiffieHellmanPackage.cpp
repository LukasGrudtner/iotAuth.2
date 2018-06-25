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

char *DiffieHellmanPackage::getNonceA()
{
    return nonceA;
}

char *DiffieHellmanPackage::getNonceB()
{
    return nonceB;
}

int DiffieHellmanPackage::getIV()
{
    return iv;
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

void DiffieHellmanPackage::setIV(int iv)
{
    this->iv = iv;
}

std::string DiffieHellmanPackage::toString()
{
    std::string result =    std::to_string(getResult())     + ":" +
                            std::to_string(getBase())       + ":" +
                            std::to_string(getModulus());

    return result;
}
