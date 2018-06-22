#ifndef ARDUINO_H
#define ARDUINO_H

#include "iotAuth.h"
#include "settings.h"
#include "utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "Diffie-Hellman/DHKeyExchange.h"
#include "Diffie-Hellman/DiffieHellmanPackage.h"
#include "Diffie-Hellman/DHStorage.h"
#include "Diffie-Hellman/DHEncPacket.h"

#include "RSA/RSAStorage.h"
#include "RSA/RSAKeyExchange.h"
#include "RSA/RSAPackage.h"

#include "verbose/verbose_client.h"
#include <sys/time.h>

using namespace std;

/* Simulação das funções executadas pelo Arduino. */

class Arduino
{
    public:

        Arduino();
        
        char *clientIP;
        char *serverIP;
        char nonceA[129];
        char nonceB[129];

        double networkTime, processingTime1, processingTime2, totalTime;
        double t1, t2;
        double t_aux1, t_aux2;

        void send_syn(States *state, int socket, struct sockaddr *server, socklen_t size);

        void recv_ack(States *state, int socket, struct sockaddr *server, socklen_t size);

        void send_rsa(States *state, int socket, struct sockaddr *server, socklen_t size);

        void recv_rsa(States *state, int socket, struct sockaddr *server, socklen_t size);

        void send_rsa_ack(States *state, int socket, struct sockaddr *server, socklen_t size);
        

        /*  Receive Diffie-Hellman
            Realiza o recebimento da chave Diffie-Hellman vinda do Servidor.
        */
        void recv_dh(States *state, int socket, struct sockaddr *server, socklen_t size);

        /*  Send Diffie-Hellman
            Realiza o envio da chave Diffie-Hellman para o Servidor.
        */
        void send_dh(States *state, int socket, struct sockaddr *client, socklen_t size);

        void recv_dh_ack(States *state, int socket, struct sockaddr *client, socklen_t size);

        void stateMachine(int socket, struct sockaddr *client, socklen_t size);

        /*  Waiting Done Confirmation
            Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
            fim de conexão enviado pelo Servidor (DONE_ACK).
            Em caso positivo, altera o estado para HELLO, senão, mantém em WDC. 7
        */
        void wdc(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Request for Termination
            Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
            vindo do Cliente, e seta o estado para HELLO.
        */
        void rft(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Hello
            Envia um pedido de início de conexão (HELLO) para o Servidor
        */
        void hello(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Done
            Envia um pedido de término de conexão ao Cliente, e seta o estado atual
            para WDC (Waiting Done Confirmation).
        */
        void done(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Data Transfer
            Realiza a transferência de dados cifrados para o Servidor.
        */
        void dt(States *state, int socket, struct sockaddr *client, socklen_t size);

        /*  Encrypt Message
            Encripta a mensagem utilizando a chave de sessão.
        */
        string encryptMessage(char* message, int size);

        /*  Setup RSA
            Inicializa os valores pertinentes a troca de chaves RSA: IV, FDR e as próprias chaves RSA.
        */
        void setupRSA();

        /*  Setup Diffie-Hellman
            Inicializa os valores pertinentes a troca de chaves Diffie-Hellman:
            expoente, base, módulo, resultado e a chave de sessão.
        */
        void storeDiffieHellman(DiffieHellmanPackage *dhPackage);

        /*  Mount Diffie-Hellman Package
            Monta o pacote Diffie-Hellman com os dados, e logo após realiza sua conversão para bytes,
            com o retorno deste array sendo por parâmetro.
        */
        void mountDHPackage(DiffieHellmanPackage *dhPackage);

        /*  Get Encrypted Hash
            Realiza a cifragem do hash obtido do pacote Diffie-Hellman com a chave privada do Servidor.
            O retorno do hash cifrado é feito por parâmetro.
        */
        int* getEncryptedHash(DiffieHellmanPackage *dhPackage);

        void generateNonce(char *nonce);

    private:

        IotAuth iotAuth;
        int sequence;

        
        RSAStorage *rsaStorage;
        DHStorage *dhStorage;

        /*  Check Answered FDR
            Verifica a validade da resposta da FDR gerada pelo Servidor.
        */
        bool checkAnsweredFDR(int answeredFdr);

        /*  Calculate FDR Value
            Calcula a resposta de uma dada FDR. */
        int calculateFDRValue(int iv, FDR* fdr);

        /*  Decrypt DH Key Exchange
            Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Cliente.
            Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
        */
        void decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange);

        /*  Get Diffie-Hellman Package
            Obtém o pacote Diffie-Hellman em bytes, o transforma de volta em objeto, e retorna por parâmetro.
        */
        void getDiffieHellmanPackage(DHKeyExchange *dhKeyExchange, DiffieHellmanPackage *diffieHellmanPackage);

        /*  Decrypt Hash
            Decifra o hash obtido do pacote utilizando a chave pública do Servidor.
            Retorna o hash em uma string.
        */
        string decryptHash(int *encryptedHash);
};

#endif
