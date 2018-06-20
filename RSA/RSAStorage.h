#ifndef RSA_STORAGE_H
#define RSA_STORAGE_H

#include "../settings.h"

class RSAStorage
{
    public:
        RSAKey* getMyPublicKey();
        RSAKey* getMyPrivateKey();
        RSAKey* getPartnerPublicKey();

        FDR* getMyFDR();

        FDR* getPartnerFDR();

        void setKeyPair(RSAKeyPair keys);
        void setPartnerPublicKey(RSAKey key);

        void setMyFDR(FDR fdr);

        void setPartnerFDR(FDR fdr);

    private:
        RSAKey myPublicKey;
        RSAKey myPrivateKey;
        RSAKey partnerPublicKey;

        FDR myFDR;
        FDR partnerFDR;

};

#endif