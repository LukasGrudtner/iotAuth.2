#include "RSAKeyExchange.h"

RSAKeyExchange::RSAKeyExchange() {
    publicKey = {0,0};
    nonceA[128] = '\0';
    nonceB[128] = '\0';
}

RSAKey RSAKeyExchange::getPublicKey() {
    return publicKey;
}

int RSAKeyExchange::getAnswerFDR() {
    return answerFdr;
}

FDR RSAKeyExchange::getFDR() {
    return fdr;
}

void RSAKeyExchange::setPublicKey(RSAKey pKey) {
    publicKey = pKey;
}

void RSAKeyExchange::setAnswerFDR(int aFdr) {
    answerFdr = aFdr;
}

void RSAKeyExchange::setFDR(FDR _fdr) {
    fdr = _fdr;
}

std::string RSAKeyExchange::toString() {
    std::string result =    std::to_string(getPublicKey().d)    + " | " +
                            std::to_string(getPublicKey().n)    + " | " +
                            std::to_string(getAnswerFDR())      + " | " +
                            getFDR().toString()                 + " | " + 
                            getNonceA()                         + " | " +
                            getNonceB();

    return result;
}

void RSAKeyExchange::setNonceA(char *nonce)
{
    for (int i = 0; i < 128; i++) {
        nonceA[i] = nonce[i];
    }
}

void RSAKeyExchange::setNonceB(char *nonce)
{
    for (int i = 0; i < 128; i++) {
        nonceB[i] = nonce[i];
    }
}

char *RSAKeyExchange::getNonceA()
{
    return nonceA;
}

char *RSAKeyExchange::getNonceB()
{
    return nonceB;
}