#include "DHEncPacket.h"
#include <iostream>

DHEncPacket::DHEncPacket()
{
    memset(encryptedExchange, 0, sizeof(encryptedExchange));
}

int *DHEncPacket::getEncryptedExchange()
{
    return encryptedExchange;
}

double DHEncPacket::getTP()
{
    return tp;
}

void DHEncPacket::setEncryptedExchange(int encryptedExchange[])
{
    for (int i = 0; i < sizeof(DHKeyExchange); i++) {
        this->encryptedExchange[i] = encryptedExchange[i];
    }
}

void DHEncPacket::setTP(double tp)
{
    this->tp = tp;
}