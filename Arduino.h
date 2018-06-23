#ifndef ARDUINO_H
#define ARDUINO_H

#include "iotAuth.h"
#include "settings.h"
#include "utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "time.h"

#include "Diffie-Hellman/DHKeyExchange.h"
#include "Diffie-Hellman/DiffieHellmanPackage.h"
#include "Diffie-Hellman/DHStorage.h"
#include "Diffie-Hellman/DHEncPacket.h"

#include "RSA/RSAStorage.h"
#include "RSA/RSAKeyExchange.h"
#include "RSA/RSAPackage.h"

#include "verbose/verbose_client.h"

using namespace std;

/* Simulação das funções executadas pelo Arduino. */

class Arduino
{
    public:

        Arduino();
        
        bool transfer_data = true;
        char *clientIP;     /*  Endereço IP do Cliente.                 */
        char *serverIP;     /*  Endereço IP do Servidor.                */
        char nonceA[129];   /*  Armazena o nonce gerado do Cliente.     */
        char nonceB[129];   /*  Armazena o nonce recebido do Servidor.  */

        double networkTime, processingTime1, processingTime2, totalTime;
        double t1, t2;
        double t_aux1, t_aux2;
        double start;



        /*  Step 1
            Envia pedido de início de conexão ao Servidor.   
        */
        void send_syn(States *state, int socket, struct sockaddr *server, socklen_t size);



        /*  Step 2
            Recebe confirmação do Servidor referente ao pedido de início de conexão.    
        */
        void recv_ack(States *state, int socket, struct sockaddr *server, socklen_t size);



        /*  Step 3
            Realiza o envio dos dados RSA para o Servidor.  
        */
        void send_rsa(States *state, int socket, struct sockaddr *server, socklen_t size);



        /*  Step 4
            Recebe os dados RSA vindos do Servidor.
        */
        void recv_rsa(States *state, int socket, struct sockaddr *server, socklen_t size);



        /*  Step 5
            Envia confirmação para o Servidor referente ao recebimento dos dados RSA.  
        */
        void send_rsa_ack(States *state, int socket, struct sockaddr *server, socklen_t size);


        
        /*  Step 6
            Realiza o recebimento dos dados Diffie-Hellman vinda do Servidor.
        */
        void recv_dh(States *state, int socket, struct sockaddr *server, socklen_t size);



        /*  Step 7
            Realiza o envio dos dados Diffie-Hellman para o Servidor.
        */
        void send_dh(States *state, int socket, struct sockaddr *client, socklen_t size);



        /*  Step 8
            Recebe a confirmação do Servidor referente aos dados Diffie-Hellman enviados.
        */
        void recv_dh_ack(States *state, int socket, struct sockaddr *client, socklen_t size);



        /*  Step 9
            Realiza a transferência de dados cifrados para o Servidor.
        */
        void data_transfer(States *state, int socket, struct sockaddr *client, socklen_t size);



        /********************************************************************************************************/
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

        /*  Done
            Envia um pedido de término de conexão ao Cliente, e seta o estado atual
            para WDC (Waiting Done Confirmation).
        */
        void done(States *state, int socket, struct sockaddr *client, socklen_t size);


        

    private:

        IotAuth iotAuth;
        int sequence;

        RSAStorage *rsaStorage;
        DHStorage *dhStorage;





        /*  Decrypt DH Key Exchange
            Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Cliente.
            Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
        */
        void decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange);

        /*  Get Diffie-Hellman Package
            Obtém o pacote Diffie-Hellman em bytes, o transforma de volta em objeto, e retorna por parâmetro.
        */
        void getDiffieHellmanPackage(DHKeyExchange *dhKeyExchange, DiffieHellmanPackage *diffieHellmanPackage);

        int* encryptHash(string *message);

        /*  Decrypt Hash
            Decifra o hash obtido do pacote utilizando a chave pública do Servidor.
            Retorna o hash em uma string.
        */
        string decryptHash(int *encryptedHash);

        /*  Store Diffie-Hellman
            Armazena os valores pertinentes a troca de chaves Diffie-Hellman:
            expoente, base, módulo, resultado e a chave de sessão.
        */
        void storeDiffieHellman(DiffieHellmanPackage *dhPackage);

        /*  Encrypt Message
            Encripta a mensagem utilizando a chave de sessão.
        */
        string encryptMessage(char* message, int size);

        /*  Generate Nonce
            Gera um novo nonce, incrementando o valor de sequência.
        */
        void generateNonce(char *nonce);



        /*  Armazena o valor do nonce B em uma variável global. */
        void storeNonceB(char *nonce);
};

#endif
