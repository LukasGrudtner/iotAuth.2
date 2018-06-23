#include "iotAuth.h"

IotAuth::IotAuth()
{
    srand(time(NULL));
}




/*  Retorna um número aleatório menor que um dado limite superior. */
int IotAuth::randomNumber(int upperBound)
{
    return rand() % upperBound;
}




/*  Gera um par de chaves RSA. */
RSAKeyPair IotAuth::generateRSAKeyPair()
{
    int p, p2, n, phi, e, d;

    p = rsa.geraPrimo(100*rsa.geraNumeroRandom());
    p2 = rsa.geraPrimo(100*rsa.geraNumeroRandom());

    //Calcula o n
	n = p * p2;

    //Calcula o quociente de euler
	phi = (p - 1)*(p2 - 1);

    //Escolhe o e para calcular a chave privada
	e = rsa.escolheE(phi, p, p2, n);

    //Escolhe o d para calcular a chave pública
	d = rsa.mdcEstendido(phi, e);

    RSAKeyPair keys = {{d, n}, {e, n}};

    return keys;
}




/*  Gera um FDR. */
FDR IotAuth::generateFDR()
{
    FDR fdr;
    fdr.setOperator('+');
    fdr.setOperand(randomNumber(100));

    return fdr;
}




/*  Cifra utilizando o algoritmo RSA, tendo como parâmetro
    uma string.
*/
int* IotAuth::encryptRSA(string* plain, RSAKey* rsaKey, int size)
{
    char plainChar[plain->length()];
    strncpy(plainChar, plain->c_str(), sizeof(plainChar));

    int* mensagemC = new int[size];
    rsa.codifica(mensagemC, plainChar, rsaKey->d, rsaKey->n, sizeof(plainChar));

    return mensagemC;
}



/*  Cifra utilizando o algoritmo RSA, tendo como parâmetro
    um array de bytes.   
*/
int* IotAuth::encryptRSA(byte plain[], RSAKey* rsaKey, int size)
{
    int* mensagemC = new int[size];
    rsa.codifica(mensagemC, plain, rsaKey->d, rsaKey->n, size);

    return mensagemC;
}




/*  Decifra utilizando o algoritmo RSA. */
byte* IotAuth::decryptRSA(int *cipher, RSAKey *rsaKey, int size)
{
    byte* plain = new byte[size];
    memset(plain, 0, sizeof(plain));
    rsa.decodifica(plain, cipher, rsaKey->d, rsaKey->n, size);

    return plain;
}




/*  Cifra com o algoritmo AES. */
uint8_t* IotAuth::encryptAES(uint8_t* plaintext, uint8_t* key, uint8_t* iv, int size)
{
    uint8_t *ciphertext = plaintext;

    struct AES_ctx ctx;
    aes.AES_init_ctx_iv(&ctx, key, iv);
    aes.AES_CBC_encrypt_buffer(&ctx, ciphertext, size);

    return ciphertext;
}




/*  Decifra com o algoritmo AES. */
uint8_t* IotAuth::decryptAES(uint8_t ciphertext[], uint8_t key[], uint8_t iv[], int size)
{
    uint8_t *plaintext = ciphertext;

    struct AES_ctx ctx;
    aes.AES_init_ctx_iv(&ctx, key, iv);
    aes.AES_CBC_decrypt_buffer(&ctx, plaintext, size);

    return plaintext;
}




/*  Verifica se a resposta do FDR está correta. */
bool IotAuth::isAnswerCorrect(FDR* fdr, int argument, int answerFdr)
{
    return fdr->getValue(argument) == answerFdr;
}




/* Verifica se o HASH dado é idêntico ao HASH da mensagem. */
bool IotAuth::isHashValid(string *message, string *hash) {
    string hash2 = this->hash(message);
    return *hash == hash2;
}




/*  Recebe uma mensagem e uma chave por parâmetro, e retorna o hash
    desta mensagem assinado com a chave.
*/
int *IotAuth::signedHash(string *message, RSAKey *key)
{
    string h = hash(message);
    return encryptRSA(&h, key, h.length());
}




/*  Retorna o hash de uma dada mensagem. */
string IotAuth::hash(string *message)
{
    return sha512(*message);
}