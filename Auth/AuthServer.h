#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H

#include <unistd.h>
#include <string.h>
#include <string>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../settings.h"
#include "../time.h"
#include "iotAuth.h"

#include "../RSA/RSAStorage.h"
#include "../RSA/RSAKeyExchange.h"
#include "../RSA/RSAPackage.h"

#include "../Diffie-Hellman/DiffieHellmanPackage.h"
#include "../Diffie-Hellman/DHKeyExchange.h"
#include "../Diffie-Hellman/DHStorage.h"
#include "../Diffie-Hellman/DHEncPacket.h"

#include "../verbose/verbose_server.h"


using namespace std;

typedef struct Socket
{
    int socket;
    struct sockaddr *client;
    socklen_t size;
} t_socket;

class Auth
{
  public:

    Auth();
    int wait();

  private:
    RSAStorage *rsaStorage;
    DHStorage *diffieHellmanStorage;
    IotAuth iotAuth;

    bool transfer_data = true;

    char *serverIP;
    char *clientIP;
    int sequence;
    char nonceA[129];
    char nonceB[129];

    double networkTime, processingTime1, processingTime2, tp, auxiliarTime, totalTime;
    double t1, t2;
    double t_aux1, t_aux2;
    double start;

    struct sockaddr_in cliente, servidor;
    int meuSocket, enviei = 0;
    socklen_t tam_cliente;
    char buffer[666];

    bool connected = false;

    /*  Armazena o valor do nonce B em uma variável global. */
    void storeNonceA(char *nonce);

    /*  Gera um valor para o nonce B.   */
    void generateNonce(char *nonce);

    /*  Decifra o hash utilizando a chave pública do Cliente. */
    string decryptHash(int *encryptedHash);

    /*  Inicializa os valores pertinentes à troca de chaves Diffie-Hellman:
    expoente, base, módulo, resultado e a chave de sessão. */
    void generateDiffieHellman();

    template <typename T>
    bool checkRFT(T &object)
    {
        int cmp = memcmp(&object, DONE_MESSAGE, strlen(DONE_MESSAGE));
        return cmp == 0;
    }

    /*  Step 1
        Recebe um pedido de início de conexão por parte do Cliente.
    */
    void recv_syn(Socket *soc);

    /*  Step 2
        Envia confirmação ao Cliente referente ao pedido de início de conexão.
    */
    void send_ack(Socket *soc);

    /*  Step 3
        Recebe os dados RSA vindos do Cliente.
    */
    void recv_rsa(Socket *soc);

    /*  Step 4
        Realiza o envio dos dados RSA para o Cliente.
    */
    void send_rsa(Socket *soc);

    /*  Step 5
        Recebe confirmação do Cliente referente ao recebimento dos dados RSA.
    */
    void recv_rsa_ack(Socket *soc);

    /*  Step 6
        Realiza o envio dos dados Diffie-Hellman para o Cliente.
    */
    void send_dh(Socket *soc);

    /*  Step 7
        Recebe os dados Diffie-Hellman vindos do Cliente.   */
    int recv_dh(Socket *soc);

    /*  Step 8
        Envia confirmação para o Cliente referente ao recebimento dos dados Diffie-Hellman.
    */
    void send_dh_ack(Socket *soc);

    /*  Data Transfer
        Realiza a transferência de dados cifrados para o Cliente.
    */
    void data_transfer(Socket *soc);

    /*  Waiting Done Confirmation
    Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
    fim de conexão enviado pelo Servidor (DONE_ACK).
    Em caso positivo, altera o estado para HELLO, senão, mantém em WDC. 7
    */
    void wdc(Socket *soc);

    /*  Request for Termination
        Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
        vindo do Cliente, e seta o estado para HELLO.
    */
    void rft(Socket *soc);

    /*  Done
        Envia um pedido de término de conexão ao Cliente, e seta o estado atual
        para WDC (Waiting Done Confirmation).
    */
    void done(Socket *soc);
};

#endif