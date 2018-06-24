#ifndef DH_STORAGE_H
#define DH_STORAGE_H

#include <cmath>
#include "../settings.h"

class DHStorage
{
    public:
        int getBase();
        int getModulus();
        int getSessionKey();

        int calculateResult();
        int calculateSessionKey(int result);

        void setSessionKey(int sessionKey);
        void setBase(int base);
        void setModulus(int modulus);
        void setExponent(int exponent);

    private:
        int exponent;   /* a */
        int base;       /* g */
        int modulus;    /* p */
        int sessionKey;
};

#endif