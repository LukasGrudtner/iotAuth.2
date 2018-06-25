#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <iostream>
#include "../settings.h"

class RSA
{
    public:

        void decodifica(byte message[], int mensagemC[], int d, int n, int quant);
        void codifica(int encrypted[], char *mensagem, int e, int n, int quant);
        void codifica(int encrypted[], byte *mensagem, int e, int n, int quant);
        long potencia(long long a, long long e, long long n);
        long long mdcEstendido(long long a, long long b);
        void divisao(long long *resto, long long *quociente, long long a, long long b);
        long long escolheE(long long phi, long long p, long long p2, long long n);
        long geraPrimo(long numero);
        long long verificaPrimo(long long p);
        long geraNumeroRandom();
        long geraNumeroMax(int n);
        int expModular(int a, int b, int n);
        char to_hex(long num);

    private:

};

#endif
