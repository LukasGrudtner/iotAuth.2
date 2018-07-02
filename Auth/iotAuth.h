#ifndef IOT_AUTH_H
#define IOT_AUTH_H

#include "../settings.h"
#include "../utils.h"
#include "../fdr.h"
#include "../RSA/RSA.h"
#include "../AES/AES.h"
#include "../SHA/sha512.h"

using namespace std;

class IotAuth
{
    protected:

    public:

        IotAuth();

        /*  Retorna um número aleatório menor que um dado limite superior. */
        int randomNumber(int upperBound);



        /*  Gera um par de chaves RSA. */
        RSAKeyPair generateRSAKeyPair();


        /*  Gera um FDR. */
        FDR generateFDR();

        

        /*  Cifra utilizando o algoritmo RSA, tendo como parâmetro
            uma string.
        */
        int* encryptRSA(string *plain, RSAKey *rsaKey, int size);


        /*  Cifra utilizando o algoritmo RSA, tendo como parâmetro
            um array de bytes.   
        */
        int* encryptRSA(byte *plain, RSAKey *rsaKey, int size);



        /*  Decifra utilizando o algoritmo RSA. */
        byte* decryptRSA(int *cipher, RSAKey *rsaKey, int size);



        /*  Cifra com o algoritmo AES. */
        uint8_t* encryptAES(uint8_t* plaintext, uint8_t* key, uint8_t* iv, int size);



        /*  Decifra com o algoritmo AES. */
        uint8_t* decryptAES(uint8_t* ciphertext, uint8_t* key, uint8_t* iv, int size);



        /*  Verifica se a resposta do FDR está correta. */
        bool isAnswerCorrect(FDR* fdr, int argument, int answerFdr);



        /*  Verifica se o Hash é compatível com a mensagem. */
        bool isHashValid(string *message, string *hash);



        /*  Recebe uma mensagem e uma chave por parâmetro, e retorna o hash
            desta mensagem assinado com a chave.
        */
        int *signedHash(string *message, RSAKey *key);



        /*  Retorna o hash de uma dada mensagem. */
        string hash(string *message);

    private:

        AES aes;    /*  Instância da classe AES.    */
        RSA rsa;    /*  Instância da classe RSA.    */
};
#endif
