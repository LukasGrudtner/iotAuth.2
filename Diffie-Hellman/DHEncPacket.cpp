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

void DHEncPacket::setEncryptedExchange(int encExchange[])
{
    for (int i = 0; i < sizeof(DHKeyExchange); i++) {
        encryptedExchange[i] = encExchange[i];
    }
}

void DHEncPacket::setTP(double _tp)
{
    tp = _tp;
}