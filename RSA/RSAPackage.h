#ifndef RSA_PACKAGE_H
#define RSA_PACKAGE_H

#include "../settings.h"
#include "../fdr.h"
#include <string.h>

using namespace std;

class RSAPackage
{
    public:
        RSAKey getPublicKey();
        FDR getFDR();
        int getAnswerFDR();
        char *getNonceA();
        char *getNonceB();
        char getACK();

        void setPublicKey(RSAKey key);
        void setFDR(FDR fdr);
        void setAnswerFDR(int answerFDR);
        void setNonceA(char *nonce);
        void setNonceB(char *nonce);
        void setACK();

        string toString();

    private:
        RSAKey publicKey;
        FDR fdr;
        int answerFDR = 0;
        char nonceA[129];
        char nonceB[129];
        char ack = '-';
};

#endif