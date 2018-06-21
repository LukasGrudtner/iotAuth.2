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

        void setSessionKey(int _sessionKey);
        void setBase(int _base);
        void setModulus(int _modulus);
        void setExponent(int _exponent);

    private:
        int exponent;   /* a */
        int base;       /* g */
        int modulus;    /* p */
        int sessionKey;
};

#endif