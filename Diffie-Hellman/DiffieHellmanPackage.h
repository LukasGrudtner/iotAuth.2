#ifndef DH_PACKAGE_H
#define DH_PACKAGE_H

#include <string.h>
#include <string>

using namespace std;

class DiffieHellmanPackage
{
    public:

        /* Getters */
        int getResult();
        int getBase();
        int getModulus();

        string getNonceA();
        string getNonceB();

        /* Setters */
        void setResult(int r);
        void setBase(int base);
        void setModulus(int modulus);

        void setNonceA(char *nonce);
        void setNonceB(char *nonce);

        std::string toString();

    private:
        int result      = 0;
        int g           = 0;    // Base
        int p           = 0;    // Modulus

        char nonceA[129];
        char nonceB[129];
};

#endif
