#ifndef RSA_KEY_EXCHANGE_H
#define RSA_KEY_EXCHANGE_H

#include "../settings.h"
#include "../fdr.h"
#include <stdio.h>
#include <string>

class RSAKeyExchange
{

    public:
        RSAKeyExchange();
        /* Getters */
        RSAKey getPublicKey();
        int getAnswerFDR();
        FDR getFDR();
        char *getNonceA();
        char *getNonceB();

        /* Setters */
        void setPublicKey(RSAKey pKey);
        void setAnswerFDR(int aFdr);
        void setFDR(FDR _fdr);
        void setNonceA(char *nonce);
        void setNonceB(char *nonce);


        std::string toString();

    private:
        RSAKey publicKey;
        FDR fdr;
        char nonceA[129];
        char nonceB[129];
        int answerFdr = 0;
        char ack = '.';

};

#endif
