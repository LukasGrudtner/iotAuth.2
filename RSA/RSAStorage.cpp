#include "RSAStorage.h"

RSAKey* RSAStorage::getMyPublicKey()
{
    return &myPublicKey;
}

RSAKey* RSAStorage::getMyPrivateKey()
{
    return &myPrivateKey;
}

RSAKey* RSAStorage::getPartnerPublicKey()
{
    return &partnerPublicKey;
}

FDR* RSAStorage::getMyFDR()
{
    return &myFDR;
}

FDR* RSAStorage::getPartnerFDR()
{
    return &partnerFDR;
}

void RSAStorage::setKeyPair(RSAKeyPair keys)
{
    myPublicKey = keys.publicKey;
    myPrivateKey = keys.privateKey;
}

void RSAStorage::setPartnerPublicKey(RSAKey key)
{
    partnerPublicKey = key;
}

void RSAStorage::setMyFDR(FDR fdr)
{
    myFDR = fdr;
}

void RSAStorage::setPartnerFDR(FDR fdr)
{
    partnerFDR = fdr;
}