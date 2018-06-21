#include "RSAPackage.h"

RSAKey RSAPackage::getPublicKey()
{
    return publicKey;
}

FDR RSAPackage::getFDR()
{
    return fdr;
}

int RSAPackage::getAnswerFDR()
{
    return answerFDR;
}

string RSAPackage::getNonceA()
{
    string nonce (nonceA);
    return nonce;
}

string RSAPackage::getNonceB()
{
    string nonce (nonceB);
    return nonceB;
}

char RSAPackage::getACK()
{
    return ack;
}

void RSAPackage::setPublicKey(RSAKey key)
{
    publicKey = key;
}

void RSAPackage::setFDR(FDR f)
{
    fdr = f;
}

void RSAPackage::setAnswerFDR(int aFdr)
{
    answerFDR = aFdr;
}

void RSAPackage::setNonceA(char *nonce)
{
    strncpy(nonceA, nonce, sizeof(nonceA));
}

void RSAPackage::setNonceB(char *nonce)
{
    strncpy(nonceB, nonce, sizeof(nonceB));
}

void RSAPackage::setACK()
{
    ack = ACK;
}

string RSAPackage::toString()
{
    std::string result =    std::to_string(publicKey.d)    + " | " +
                        std::to_string(publicKey.n)    + " | " +
                        std::to_string(answerFDR)      + " | " +
                        fdr.toString()                 + " | " + 
                        nonceA                         + " | " +
                        nonceB;
    return result;
}