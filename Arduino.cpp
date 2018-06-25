#include "Arduino.h"

Arduino::Arduino()
{
    nonceA[128] = '\0';
    nonceB[128] = '\0';
}




/*  Step 1
    Envia pedido de início de conexão ao Servidor.   
*/
void Arduino::send_syn(States *state, int socket, struct sockaddr *server, const socklen_t size)
{
    start = currentTime();

    /******************** Init Sequence ********************/
    sequence = iotAuth.randomNumber(9999);
    
    /******************** Generate Nonce ********************/
    generateNonce(nonceA);

    /******************** Mount SYN Package ********************/
    structSyn toSend;
    strncpy(toSend.nonce, nonceA, sizeof(toSend.nonce));

    /******************** Start Network Time ********************/
    t1 = currentTime();

    /******************** Send SYN ********************/
    sendto(socket, (syn*)&toSend, sizeof(syn), 0, server, size);
    *state = RECV_ACK;

    /******************** Verbose ********************/
    if (VERBOSE) send_syn_verbose(nonceA);
}




/*  Step 2
    Recebe confirmação do Servidor referente ao pedido de início de conexão.    
*/
void Arduino::recv_ack(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Receive ACK ********************/
    structAck received;
    int recv = recvfrom(socket, &received, sizeof(ack), 0, server, &size);

    if (recv > 0) {

        /******************** Stop Network Time ********************/
        t2 = currentTime();
        networkTime = elapsedTime(t1, t2);

        /******************** Start Processing Time ********************/
        t1 = currentTime();

        /******************** Store Nonce B ********************/
        storeNonceB(received.nonceB);

        /******************** Validity Message ********************/
        const bool isNonceTrue = (strcmp(received.nonceA, nonceA) == 0);

        if (isNonceTrue) {
            *state = SEND_RSA;
        } else {
            *state = SEND_SYN;
        }

        /******************** Verbose ********************/
        if (VERBOSE) recv_ack_verbose(nonceB, sequence, serverIP, clientIP, isNonceTrue);
    } else {
        loop = false;
        if (VERBOSE) response_timeout_verbose();
    }
}




/*  Step 3
    Realiza o envio dos dados RSA para o Servidor.  
*/
void Arduino::send_rsa(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Generate RSA/FDR ********************/
    rsaStorage = new RSAStorage();
    rsaStorage->setKeyPair(iotAuth.generateRSAKeyPair());
    rsaStorage->setMyFDR(iotAuth.generateFDR());

    /******************** Generate Nonce ********************/
    generateNonce(nonceA);

    /******************** Mount Package ********************/
    RSAPackage rsaSent;
    rsaSent.setPublicKey(*rsaStorage->getMyPublicKey());
    rsaSent.setFDR(*rsaStorage->getMyFDR());
    rsaSent.setNonceA(nonceA);
    rsaSent.setNonceB(nonceB);

    /******************** Get Hash ********************/
    string rsaString = rsaSent.toString();
    int* const encryptedHash = iotAuth.signedHash(&rsaString, rsaStorage->getMyPrivateKey());

    /******************** Stop Processing Time ********************/
    t2 = currentTime();
    processingTime1 = elapsedTime(t1, t2);

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);
    rsaExchange.setProcessingTime(processingTime1);

    /******************** Start Total Time ********************/
    t1 = currentTime();

    /******************** Send Exchange ********************/
    sendto(socket, (RSAKeyExchange*)&rsaExchange, sizeof(rsaExchange), 0, server, size);
    *state = RECV_RSA;

    delete[] encryptedHash;

    /******************** Verbose ********************/
    if (VERBOSE) send_rsa_verbose(rsaStorage, sequence, nonceA);
}




/*  Step 4
    Recebe os dados RSA vindos do Servidor.
*/
void Arduino::recv_rsa(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Receive Exchange ********************/
    RSAKeyExchange* const rsaKeyExchange = new RSAKeyExchange();
    int recv = recvfrom(socket, rsaKeyExchange, sizeof(RSAKeyExchange), 0, server, &size);

    if (recv > 0) {
        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        /******************** Proof of Time ********************/
        const double limit = processingTime1 + networkTime + (processingTime1 + networkTime)*0.1;

        if (totalTime <= 2000) {
            /******************** Get Package ********************/
            RSAPackage* const rsaPackage = rsaKeyExchange->getRSAPackage();

            /******************** Config RSA ********************/
            rsaStorage->setPartnerPublicKey(rsaPackage->getPublicKey());
            rsaStorage->setPartnerFDR(rsaPackage->getFDR());
            storeNonceB(rsaPackage->getNonceB());

            /******************** Decrypt Hash ********************/
            string rsaString = rsaPackage->toString();
            string decryptedHash = decryptHash(rsaKeyExchange->getEncryptedHash());

            /******************** Validity ********************/
            const bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
            const bool isNonceTrue = strcmp(rsaPackage->getNonceA(), nonceA) == 0;
            const bool isAnswerCorrect = iotAuth.isAnswerCorrect(rsaStorage->getMyFDR(), rsaStorage->getMyPublicKey()->d, rsaPackage->getAnswerFDR());

            if (isHashValid && isNonceTrue && isAnswerCorrect) {
                *state = SEND_RSA_ACK;
            } else {
                *state = SEND_SYN;
            }

            if (VERBOSE) recv_rsa_verbose(rsaStorage, nonceB, isHashValid, isNonceTrue, isAnswerCorrect);
        
        } else {
            if (VERBOSE) time_limit_burst_verbose();
            *state = SEND_SYN;
        }
    } else {
        loop = false;
        if (VERBOSE) response_timeout_verbose();
    }

    delete rsaKeyExchange;
}




/*  Step 5
    Envia confirmação para o Servidor referente ao recebimento dos dados RSA.  
*/
void Arduino::send_rsa_ack(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Get Answer FDR ********************/
    const int answerFdr = rsaStorage->getPartnerFDR()->getValue(rsaStorage->getPartnerPublicKey()->d);
    
    /******************** Generate Nonce ********************/
    generateNonce(nonceA);

    /******************** Mount Package ********************/
    RSAPackage rsaSent;
    rsaSent.setNonceA(nonceA);
    rsaSent.setNonceB(nonceB);
    rsaSent.setAnswerFDR(answerFdr);
    rsaSent.setACK();

    /******************** Get Hash ********************/
    string rsaString = rsaSent.toString();
    int* const encryptedHash = iotAuth.signedHash(&rsaString, rsaStorage->getMyPrivateKey());

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);

    /******************** Start Total Time ********************/
    t1 = currentTime();

    /******************** Send Exchange ********************/
    sendto(socket, (RSAKeyExchange*)&rsaExchange, sizeof(rsaExchange), 0, server, size);
    *state = RECV_DH;

    delete[] encryptedHash;

    /******************** Verbose ********************/
    if (VERBOSE) send_rsa_ack_verbose(sequence, nonceA);
}




/*  Step 6
    Realiza o recebimento dos dados Diffie-Hellman vinda do Servidor.
*/
void Arduino::recv_dh(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Recv Enc Packet ********************/
    DHEncPacket encPacket;
    int recv = recvfrom(socket, &encPacket, sizeof(DHEncPacket), 0, server, &size);

    if (recv > 0) {

        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        byte* message = new byte[sizeof(DHEncPacket)];
        ObjectToBytes(encPacket, message, sizeof(DONE_MESSAGE));

        if (checkRequestForTermination(message)) {
            *state = RFT;
        } else {
            /******************** Time of Proof ********************/
            if (totalTime <= 2000) {

                /******************** Start Processing Time 2 ********************/
                t_aux1 = currentTime();

                /******************** Decrypt Exchange ********************/
                DHKeyExchange dhKeyExchange;
                int* const encryptedExchange = encPacket.getEncryptedExchange();
                byte* const dhExchangeBytes = iotAuth.decryptRSA(encryptedExchange, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));
                
                BytesToObject(dhExchangeBytes, dhKeyExchange, sizeof(DHKeyExchange));
                delete[] dhExchangeBytes;

                /******************** Get DH Package ********************/
                DiffieHellmanPackage dhPackage = dhKeyExchange.getDiffieHellmanPackage();

                /******************** Decrypt Hash ********************/
                string decryptedHash = decryptHash(dhKeyExchange.getEncryptedHash());

                /******************** Validity ********************/
                string dhString = dhPackage.toString();
                const bool isHashValid = iotAuth.isHashValid(&dhString, &decryptedHash);
                const bool isNonceTrue = strcmp(dhPackage.getNonceA(), nonceA) == 0;

                if (isHashValid && isNonceTrue) {
                    /******************** Store Nounce B ********************/
                    storeNonceB(dhPackage.getNonceB());

                    /******************** Store DH Package ********************/
                    storeDiffieHellman(&dhPackage);

                    *state = SEND_DH;
                } else {
                    *state = SEND_SYN;
                }

                if (VERBOSE) recv_dh_verbose(&dhPackage, isHashValid, isNonceTrue);

            } else {
                if (VERBOSE) time_limit_burst_verbose();
                *state = DONE;
            }
        }
    } else {
        loop = false;
        if (VERBOSE) response_timeout_verbose();
    }
}




/*  Step 7
    Realiza o envio dos dados Diffie-Hellman para o Servidor.
*/
void Arduino::send_dh(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /***************** Calculate DH ******************/
    const int sessionKey = dhStorage->calculateSessionKey(dhStorage->getSessionKey());
    const int result = dhStorage->calculateResult();
    dhStorage->setSessionKey(sessionKey);

    /***************** Generate Nonce A ******************/
    generateNonce(nonceA);

    /***************** Mount Package ******************/
    DiffieHellmanPackage diffieHellmanPackage;
    diffieHellmanPackage.setResult(result);
    diffieHellmanPackage.setNonceA(nonceA);
    diffieHellmanPackage.setNonceB(nonceB);

    /***************** Encrypt Hash ******************/
    string dhString = diffieHellmanPackage.toString();
    int* const encryptedHash = iotAuth.signedHash(&dhString, rsaStorage->getMyPrivateKey());

    /***************** Stop Processing Time 2 ******************/
    t2 = currentTime();
    processingTime2 = elapsedTime(t1, t2);

    /********************** Mount Exchange ************************/
    DHKeyExchange dhSent;
    dhSent.setEncryptedHash(encryptedHash);
    dhSent.setDiffieHellmanPackage(diffieHellmanPackage);

    /********************** Serialize Exchange **********************/
    byte* const exchangeBytes = new byte[sizeof(DHKeyExchange)];
    ObjectToBytes(dhSent, exchangeBytes, sizeof(DHKeyExchange));

    /********************** Encrypt Exchange **********************/
    int* const encryptedExchange = iotAuth.encryptRSA(exchangeBytes, rsaStorage->getPartnerPublicKey(), sizeof(RSAKeyExchange));

    /********************** Mount Enc Packet **********************/
    DHEncPacket encPacket;
    encPacket.setEncryptedExchange(encryptedExchange);
    encPacket.setTP(processingTime2);

    /******************** Start Total Time ********************/
    t1 = currentTime();

    /******************** Send Enc Packet ********************/
    sendto(socket, (DHEncPacket*)&encPacket, sizeof(DHEncPacket), 0, server, size);
    *state = RECV_DH_ACK;

    /******************** Verbose ********************/
    if (VERBOSE) send_dh_verbose(&diffieHellmanPackage, sessionKey, sequence, encPacket.getTP());

    delete[] exchangeBytes;
    delete[] encryptedHash;
    delete[] encryptedExchange;
}




/*  Step 8
    Recebe a confirmação do Servidor referente aos dados Diffie-Hellman enviados.
*/
void Arduino::recv_dh_ack(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Recv ACK ********************/
    int encryptedACK[sizeof(DH_ACK)];
    int recv = recvfrom(socket, encryptedACK, sizeof(DH_ACK)*sizeof(int), 0, server, &size);

    if (recv > 0) {

        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        /******************** Proof of Time ********************/
        const double limit = processingTime2 + networkTime + (processingTime2 + networkTime)*0.1;

        if (totalTime <= limit) {

            /******************** Decrypt ACK ********************/
            byte* const decryptedACKBytes = iotAuth.decryptRSA(encryptedACK, rsaStorage->getPartnerPublicKey(), sizeof(DH_ACK));

            /******************** Deserialize ACK ********************/
            DH_ACK ack;
            BytesToObject(decryptedACKBytes, ack, sizeof(DH_ACK));
            delete[] decryptedACKBytes;

            /******************** Validity ********************/
            const bool isNonceTrue = (strcmp(ack.nonce, nonceA) == 0);

            if (isNonceTrue) {
                *state = SEND_DATA;
            } else {
                *state = SEND_SYN;
            }

            /******************** Verbose ********************/
            if (VERBOSE) send_dh_ack_verbose(&ack, isNonceTrue);

        } else {
            if (VERBOSE) time_limit_burst_verbose();
            *state = SEND_SYN;
        }
        if (MEM_TEST) loop = false;
    } else {
        loop = false;
        if (VERBOSE) response_timeout_verbose();
    }
}




/*  Step 9
    Realiza a transferência de dados cifrados para o Servidor.
*/
void Arduino::data_transfer(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    delete rsaStorage;

    char envia[666];
    memset(envia, '\0', sizeof(envia));

    if (VERBOSE) {dt_verbose1();}
    
    /* Captura a mensagem digitada no terminal para a criptografia. */
    fgets(envia, 666, stdin);

    /* Enquanto o usuário não digitar um 'Enter': */
    while (strcmp(envia, "\n") != 0) {

        /* Encripta a mensagem digitada pelo usuário. */
        string encryptedMessage = encryptMessage(envia, sizeof(envia));
        if (VERBOSE) {dt_verbose2(&encryptedMessage);}

        /* Converte a string em um array de char. */
        char encryptedMessageChar[encryptedMessage.length()];
        memset(encryptedMessageChar, '\0', sizeof(encryptedMessageChar));
        strncpy(encryptedMessageChar, encryptedMessage.c_str(), sizeof(encryptedMessageChar));

        /* Envia a mensagem cifrada ao Servidor. */
        sendto(socket, encryptedMessageChar, strlen(encryptedMessageChar), 0, server, size);
        memset(envia, '\0', sizeof(envia));
        fgets(envia, 665, stdin);
    }
}




/*  Armazena o valor do nonce B em uma variável global. */
void Arduino::storeNonceB(char *nonce)
{
    strncpy(nonceB, nonce, sizeof(nonceB));
}

/***********************************************************************************************/

/*  State Machine
    Realiza o controle do estado atual da FSM.
*/
void Arduino::stateMachine(int socket, struct sockaddr *server, socklen_t size)
{
    static States state = SEND_SYN;

    switch (state) {

        /* Waiting Done Confirmation */
        case WDC:
        {
            cout << "WAITING DONE CONFIRMATION" << endl;
            wdc(&state, socket, server, size);
            break;
        }

        /* Request For Termination */
        case RFT:
        {
            cout << "REQUEST FOR TERMINATION RECEIVED" << endl;
            rft(&state, socket, server, size);
            break;
        }

        /* Done */
        case DONE:
        {
            cout << "SEND DONE" << endl;
            done(&state, socket, server, size);
            break;
        }

        /* Hello */
        case SEND_SYN:
        {
            send_syn(&state, socket, server, size);
            break;
        }

        /* Hello */
        case RECV_ACK:
        {
            recv_ack(&state, socket, server, size);
            break;
        }

        /* Receive RSA */
        case RECV_RSA:
        {
            recv_rsa(&state, socket, server, size);
            break;
        }

        /* Send RSA */
        case SEND_RSA:
        {
            send_rsa(&state, socket, server, size);
            break;
        }

        case SEND_RSA_ACK:
        {
            send_rsa_ack(&state, socket, server, size);
            break;
        }

        /* Receive Diffie-Hellman */
        case RECV_DH:
        {
            recv_dh(&state, socket, server, size);
            break;
        }

        /* Send Diffie-Hellman */
        case SEND_DH:
        {
            send_dh(&state, socket, server, size);
            break;
        }

        case RECV_DH_ACK:
        {
            recv_dh_ack(&state, socket, server, size);
            break;
        }

        /* Data Transfer */
        case SEND_DATA:
        {
            data_transfer(&state, socket, server, size);
            break;
        }
    }
}

/*  Waiting Done Confirmation
    Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
    fim de conexão enviado pelo Servidor (DONE_ACK).
    Em caso positivo, altera o estado para HELLO, senão, mantém em WDC. 7
*/
void Arduino::wdc(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    char message[2];
    recvfrom(socket, message, sizeof(message), 0, server, &size);

    if (message[0] == DONE_ACK_CHAR) {
        *state = RECV_ACK;
    } else {
        *state = WDC;
    }
}

/*  Request for Termination
    Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
    vindo do Cliente, e seta o estado para HELLO.
*/
void Arduino::rft(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    sendto(socket, DONE_ACK, strlen(DONE_ACK), 0, server, size);
    *state = RECV_ACK;

    if (VERBOSE) {rft_verbose();}
}





/*  Done
    Envia um pedido de término de conexão ao Cliente, e seta o estado atual
    para WDC (Waiting Done Confirmation).
*/
void Arduino::done(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    sendto(socket, DONE_MESSAGE, strlen(DONE_MESSAGE), 0, server, size);
    *state = WDC;
}

void Arduino::generateNonce(char *nonce)
{
    string message = stringTime() + *clientIP + *serverIP + to_string(sequence++);
    string hash = iotAuth.hash(&message);

    memset(nonce, '\0', 129);
    strncpy(nonce, hash.c_str(), 128);
}


void Arduino::storeDiffieHellman(DiffieHellmanPackage *dhPackage)
{
    dhStorage = new DHStorage();

    dhStorage->setExponent(iotAuth.randomNumber(3)+2);
    dhStorage->setBase(dhPackage->getBase());
    dhStorage->setModulus(dhPackage->getModulus());
    dhStorage->setSessionKey(dhPackage->getResult());
    dhStorage->setIV(dhPackage->getIV());
}





/*  Decrypt DH Key Exchange
    Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Servidor.
    Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
*/
void Arduino::decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange)
{
    byte* const decryptedMessage = iotAuth.decryptRSA(encryptedMessage, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));
    
    BytesToObject(decryptedMessage, *dhKeyExchange, sizeof(DHKeyExchange));

    delete[] decryptedMessage;
}

/*  Decrypt Hash
    Decifra o hash obtido do pacote utilizando a chave pública do Cliente.
    Retorna o hash em uma string.
*/
string Arduino::decryptHash(int *encryptedHash)
{
    byte* const decryptedHash = iotAuth.decryptRSA(encryptedHash, rsaStorage->getPartnerPublicKey(), 128);

    char aux;
    string decryptedHashString = "";
    for (int i = 0; i < 128; i++) {
        aux = decryptedHash[i];
        decryptedHashString += aux;
    }

    delete[] decryptedHash;

    return decryptedHashString;
}

/*  Data Transfer
    Realiza a transferência de dados cifrados para o Servidor.
*/


/*  Encrypt Message
    Encripta a mensagem utilizando a chave de sessão.
*/
string Arduino::encryptMessage(char* message, int size) 
{
    /* Inicialização do vetor plaintext. */
    uint8_t plaintext[size];
    memset(plaintext, 0, size);

    /* Inicialização da chave e do IV. */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = dhStorage->getSessionKey();
    }

    uint8_t iv[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = dhStorage->getIV();
    }

    /* Converte o array de char (message) para uint8_t. */
    CharToUint8_t(message, plaintext, size);

    /* Encripta a mensagem utilizando a chave e o iv declarados anteriormente. */
    uint8_t* const encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    const string result = Uint8_tToHexString(encrypted, size);

    return result;
}

bool Arduino::checkRequestForTermination(byte* message)
{
    char aux[strlen(DONE_MESSAGE)+1];
    aux[strlen(DONE_MESSAGE)] = '\0';

    for (int i = 0; i < strlen(DONE_MESSAGE); i++) {
        aux[i] = (char)message[i];
    }

    /* Verifica se a mensagem recebida é um DONE. */
    if (strcmp(aux, DONE_MESSAGE) == 0) {
        return true;
    } else {
        return false;
    }
}
