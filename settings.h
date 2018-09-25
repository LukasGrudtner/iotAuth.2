#ifndef SETTINGS_H
#define SETTINGS_H

#include "fdr.h"

#define MEM_TEST false

#define COUNT 3 /* Limite de tempo que irá esperar pelo ACK */

/* Definição de alguns atributos utilizados na comunicação */
#define VERBOSE true
#define DEFAULT_PORT 8080

#define DONE_MESSAGE "DONE"

#define DONE_ACK "!"
#define DONE_ACK_CHAR '!'

#define ACK true
#define ACK_CHAR '*'
#define SYN false

/* Maximum time wait for response */
#define TIMEOUT_SEC 5
#define TIMEOUT_MIC 0

typedef struct syn
{
    bool message = SYN;
    uint8_t nonce[32];    /* HASH(time | idDestino | idOrigem | seq) */
} structSyn;

typedef struct ack
{
    bool message = ACK;
    char nonceA[129];
    char nonceB[129];
} structAck;

typedef struct DH_ACK 
{
    bool message = ACK;
    char nonce[129];
} DH_ACK;

/* Definição do tipo "byte" utilizado. */
typedef unsigned char byte;

/* Definição da struct de chave RSA. */
typedef struct rsa_key
{
    int d, n;
} RSAKey;

/* Definição da struct que contém o par de chaves RSA. */
typedef struct rsa_key_pair
{
    RSAKey publicKey;
    RSAKey privateKey;
} RSAKeyPair;

typedef enum {
    OK,
    DENIED,
    TIMEOUT,
    NO_REPLY,
    NONCE_INVALID,
    FDR_INVALID,
    HASH_INVALID,
    FINISHED,
    NOT_CONNECTED,
} status;

#endif