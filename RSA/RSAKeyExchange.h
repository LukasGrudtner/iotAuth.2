#ifndef RSA_KEY_EXCHANGE_H
#define RSA_KEY_EXCHANGE_H

#include "../settings.h"
#include "../fdr.h"
#include "RSAPackage.h"
#include <stdio.h>
#include <string>

class RSAKeyExchange
{

    public:
        RSAPackage *getRSAPackage();
        int *getEncryptedHash();
        double getProcessingTime();

        void setRSAPackage(RSAPackage *rsaP);
        void setEncryptedHash(int encHash[]);
        void setProcessingTime(double processingTime);

    private:
        RSAPackage rsaPackage;
        int encryptedHash[128];
        double tp;

};

#endif
