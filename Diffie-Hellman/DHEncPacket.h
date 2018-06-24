#ifndef DH_ENC_PACKET_H
#define DH_ENC_PACKET_H

#include "../settings.h"
#include <string.h>
#include "DHKeyExchange.h"

class DHEncPacket 
{
    public:
        DHEncPacket();

        int *getEncryptedExchange();
        double getTP();

        void setEncryptedExchange(int encryptedExchange[]);
        void setTP(double tp);

    private:
        int encryptedExchange[sizeof(DHKeyExchange)];
        double tp;
};

#endif