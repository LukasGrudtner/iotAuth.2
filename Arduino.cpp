#include "Arduino.h"

Arduino::Arduino()
{
    nonceA[128] = '\0';
    nonceB[128] = '\0';
}

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
    // char message[1];
    // recvfrom(socket, message, sizeof(message), 0, server, &size);

    // if (message[0] == DONE_ACK_CHAR) {
    //     *state = HELLO;
    // } else {
    //     *state = WDC;
    // }
}

/*  Request for Termination
    Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
    vindo do Cliente, e seta o estado para HELLO.
*/
void Arduino::rft(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    // sendto(socket, DONE_ACK, strlen(DONE_ACK), 0, server, size);
    // *state = HELLO;

    // if (VERBOSE) {rft_verbose();}
}

void Arduino::send_syn(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Init Sequence ********************/
    sequence = iotAuth.randomNumber(9999);
    
    /******************** Generate Nonce ********************/
    generateNonce(nonceA);

    /******************** Mount SYN Package ********************/
    structSyn toSend;
    strncpy(toSend.nonce, nonceA, sizeof(toSend.nonce));

    /******************** Start Network Time ********************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t1 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;

    /******************** Send SYN ********************/
    sendto(socket, (syn*)&toSend, sizeof(syn), 0, server, size);
    *state = RECV_ACK;

    /******************** Verbose ********************/
    if (VERBOSE) send_syn_verbose(nonceA);
}

void Arduino::recv_ack(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Receive ACK ********************/
    structAck received;
    recvfrom(socket, &received, sizeof(ack), 0, server, &size);

    /******************** Stop Network Time ********************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t2 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;
    networkTime = (double)(t2-t1)*1000;

    /******************** Start Processing Time ********************/
    gettimeofday(&tv, NULL);
    t1 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;

    /******************** Store Nonce B ********************/
    strncpy(nonceB, received.nonceB, sizeof(nonceB));

    /******************** Validity Message ********************/
    bool isNonceTrue = (strcmp(received.nonceA, nonceA) == 0);

    if (isNonceTrue) {
        *state = SEND_RSA;
    } else {
        *state = SEND_SYN;
    }

    /******************** Verbose ********************/
    if (VERBOSE) recv_ack_verbose(nonceB, sequence, serverIP, clientIP, isNonceTrue);
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

void Arduino::send_rsa_ack(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Get Answer FDR ********************/
    int answerFdr = calculateFDRValue(rsaStorage->getPartnerPublicKey()->d, rsaStorage->getPartnerFDR());
    
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
    string hash = iotAuth.hash(&rsaString);

    /******************** Encrypt Hash ********************/
    int *encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);

    /******************** Start Total Time ********************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t1 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;

    /******************** Send Exchange ********************/
    int sended = sendto(socket, (RSAKeyExchange*)&rsaExchange, sizeof(rsaExchange), 0, server, size);
    *state = RECV_DH;

    /******************** Verbose ********************/
    if (VERBOSE) send_rsa_ack_verbose(sequence, nonceA);
}

/*  Send RSA
    Realiza o envio da chave RSA para o Servidor.
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
    string hash = iotAuth.hash(&rsaString);

    /******************** Encrypt Hash ********************/
    int *encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());

    /******************** Stop Processing Time ********************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t2 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;
    processingTime1 = (double)(t2-t1)*1000;

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);
    rsaExchange.setProcessingTime(processingTime1);

    /******************** Start Total Time ********************/
    gettimeofday(&tv, NULL);
    t1 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;

    /******************** Send Exchange ********************/
    int sended = sendto(socket, (RSAKeyExchange*)&rsaExchange, sizeof(rsaExchange), 0, server, size);
    *state = RECV_RSA;

    /******************** Verbose ********************/
    if (VERBOSE) send_rsa_verbose(rsaStorage, sequence, nonceA);
}

/*  Receive RSA
    Realiza o recebimento da chave RSA vinda do Servidor.
*/
void Arduino::recv_rsa(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Receive Exchange ********************/
    RSAKeyExchange *rsaKeyExchange = new RSAKeyExchange();
    recvfrom(socket, rsaKeyExchange, sizeof(RSAKeyExchange), 0, server, &size);

    /******************** Stop Total Time ********************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t2 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;
    totalTime = (double)(t2-t1)*1000;

    /******************** Proof of Time ********************/
    double limit = processingTime1 + networkTime + (processingTime1 + networkTime)*0.1;

    if (totalTime <= limit) {
        /******************** Get Package ********************/
        RSAPackage *rsaPackage = rsaKeyExchange->getRSAPackage();

        /******************** Config RSA ********************/
        rsaStorage->setPartnerPublicKey(rsaPackage->getPublicKey());
        rsaStorage->setPartnerFDR(rsaPackage->getFDR());
        strncpy(nonceB, rsaPackage->getNonceB().c_str(), sizeof(nonceB));

        /******************** Decrypt Hash ********************/
        string rsaString = rsaPackage->toString();
        string decryptedHash = decryptHash(rsaKeyExchange->getEncryptedHash());

        bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
        bool isNonceTrue = rsaPackage->getNonceA() == nonceA;
        bool isAnswerCorrect = checkAnsweredFDR(rsaPackage->getAnswerFDR());

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

    delete rsaKeyExchange;
}

void Arduino::storeDiffieHellman(DiffieHellmanPackage *dhPackage)
{
    dhStorage = new DHStorage();

    dhStorage->setExponent(iotAuth.randomNumber(3)+2);
    dhStorage->setBase(dhPackage->getBase());
    dhStorage->setModulus(dhPackage->getModulus());
    dhStorage->setSessionKey(dhPackage->getResult());
}

/*  Get Encrypted Hash
    Realiza a cifragem do hash obtido do pacote Diffie-Hellman com a chave privada do Servidor.
    O retorno do hash cifrado é feito por parâmetro.
*/
int* Arduino::getEncryptedHash(DiffieHellmanPackage *dhPackage)
{
    string dhString = dhPackage->toString();
    string hash = iotAuth.hash(&dhString);

    int *encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());
    return encryptedHash;
}

/*  Send Diffie-Hellman
    Realiza o envio da chave Diffie-Hellman para o Servidor.
*/
void Arduino::send_dh(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /***************** Calculate DH ******************/
    int sessionKey = dhStorage->calculateSessionKey(dhStorage->getSessionKey());
    int result = dhStorage->calculateResult();
    dhStorage->setSessionKey(sessionKey);

    /***************** Generate Nonce A ******************/
    generateNonce(nonceA);

    /***************** Mount Package ******************/
    DiffieHellmanPackage diffieHellmanPackage;
    diffieHellmanPackage.setResult(result);
    diffieHellmanPackage.setNonceA(nonceA);
    diffieHellmanPackage.setNonceB(nonceB);

    /***************** Get Hash ******************/
    string dhString = diffieHellmanPackage.toString();
    string hash = iotAuth.hash(&dhString);

    /***************** Encrypt Hash ******************/
    int *encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());

    /***************** Stop Processing Time 2 ******************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t2 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;
    processingTime2 = (double)(t2-t1)*1000;

    /********************** Mount Exchange ************************/
    DHKeyExchange dhSent;
    dhSent.setEncryptedHash(encryptedHash);
    dhSent.setDiffieHellmanPackage(diffieHellmanPackage);

    /********************** Serialize Exchange **********************/
    byte* exchangeBytes = new byte[sizeof(DHKeyExchange)];
    ObjectToBytes(dhSent, exchangeBytes, sizeof(DHKeyExchange));

    /********************** Encrypt Exchange **********************/
    int *encryptedExchange = iotAuth.encryptRSA(exchangeBytes, rsaStorage->getPartnerPublicKey(), sizeof(RSAKeyExchange));

    /********************** Mount Enc Packet **********************/
    DHEncPacket encPacket;
    encPacket.setEncryptedExchange(encryptedExchange);
    encPacket.setTP(processingTime2);

    /******************** Start Total Time ********************/
    gettimeofday(&tv, NULL);
    t1 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;

    /******************** Send Enc Packet ********************/
    sendto(socket, (DHEncPacket*)&encPacket, sizeof(DHEncPacket), 0, server, size);
    *state = RECV_DH_ACK;

    /******************** Verbose ********************/
    if (VERBOSE) send_dh_verbose(&diffieHellmanPackage, sessionKey, sequence, encPacket.getTP());

    delete[] exchangeBytes;
    delete[] encryptedHash;
    delete[] encryptedExchange;
}

/*  Receive Diffie-Hellman
    Realiza o recebimento da chave Diffie-Hellman vinda do Servidor.
*/
void Arduino::recv_dh(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Recv Enc Packet ********************/
    DHEncPacket encPacket;
    recvfrom(socket, &encPacket, sizeof(DHEncPacket), 0, server, &size);

    /******************** Stop Total Time ********************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t2 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;
    totalTime = (double)(t2-t1)*1000;

    /******************** Time of Proof ********************/
    if (totalTime <= 5000) {

        /******************** Start Processing Time 2 ********************/
        struct timeval tv;
        gettimeofday(&tv, NULL);
        t_aux1 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;

        /******************** Decrypt Exchange ********************/
        DHKeyExchange dhKeyExchange;
        int *encryptedExchange = encPacket.getEncryptedExchange();
        byte *dhExchangeBytes = iotAuth.decryptRSA(encryptedExchange, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));
        
        BytesToObject(dhExchangeBytes, dhKeyExchange, sizeof(DHKeyExchange));

        /******************** Get DH Package ********************/
        DiffieHellmanPackage dhPackage = dhKeyExchange.getDiffieHellmanPackage();

        /******************** Decrypt Hash ********************/
        string decryptedHash = decryptHash(dhKeyExchange.getEncryptedHash());

        /******************** Validity ********************/
        string dhString = dhPackage.toString();
        bool isHashValid = iotAuth.isHashValid(&dhString, &decryptedHash);
        bool isNonceTrue = (dhPackage.getNonceA() == nonceA);

        if (isHashValid && isNonceTrue) {
            /******************** Store Nounce B ********************/
            strncpy(nonceB, dhPackage.getNonceB().c_str(), sizeof(nonceB));

            /******************** Store DH Package ********************/
            storeDiffieHellman(&dhPackage);

            *state = SEND_DH;
        } else {
            *state = SEND_SYN;
        }

        if (VERBOSE) recv_dh_verbose(&dhPackage, isHashValid, isNonceTrue);

    } else {
        if (VERBOSE) time_limit_burst_verbose();
        *state = SEND_SYN;
    }
}

void Arduino::recv_dh_ack(States *state, int socket, struct sockaddr *server, socklen_t size)
{
    /******************** Recv ACK ********************/
    int encryptedACK[sizeof(DH_ACK)];
    recvfrom(socket, encryptedACK, sizeof(DH_ACK)*sizeof(int), 0, server, &size);

    /******************** Stop Total Time ********************/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    t2 = (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;
    totalTime = (double)(t2-t1)*1000;

    /******************** Proof of Time ********************/
    double limit = processingTime2 + networkTime + (processingTime2 + networkTime)*0.1;

    if (totalTime <= limit) {

        /******************** Decrypt ACK ********************/
        byte *decryptedACKBytes = iotAuth.decryptRSA(encryptedACK, rsaStorage->getPartnerPublicKey(), sizeof(DH_ACK));

        /******************** Deserialize ACK ********************/
        DH_ACK ack;
        BytesToObject(decryptedACKBytes, ack, sizeof(DH_ACK));

        /******************** Validity ********************/
        bool isNonceTrue = (strcmp(ack.nonce, nonceA) == 0);

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
}

/*  Decrypt DH Key Exchange
    Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Servidor.
    Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
*/
void Arduino::decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange)
{
    byte* decryptedMessage = iotAuth.decryptRSA(encryptedMessage, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));
    
    BytesToObject(decryptedMessage, *dhKeyExchange, sizeof(DHKeyExchange));

    delete[] decryptedMessage;
}

/*  Decrypt Hash
    Decifra o hash obtido do pacote utilizando a chave pública do Cliente.
    Retorna o hash em uma string.
*/
string Arduino::decryptHash(int *encryptedHash)
{
    byte *decryptedHash = iotAuth.decryptRSA(encryptedHash, rsaStorage->getPartnerPublicKey(), 128);

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

/*  Calculate FDR Value
    Calcula a resposta de uma dada FDR. */
int Arduino::calculateFDRValue(int iv, FDR* fdr)
{
    int result = 0;
    if (fdr->getOperator() == '+') {
        result = iv+fdr->getOperand();
    }

    return result;
}

/*  Check Answered FDR
    Verifica a validade da resposta da FDR gerada pelo Servidor.
*/
bool Arduino::checkAnsweredFDR(int answeredFdr)
{
    int answer = calculateFDRValue(rsaStorage->getMyPublicKey()->d, rsaStorage->getMyFDR());
    return answer == answeredFdr;
}

/*  Encrypt Message
    Encripta a mensagem utilizando a chave de sessão.
*/
string Arduino::encryptMessage(char* message, int size) 
{
    /* Inicialização do vetor plaintext. */
    uint8_t plaintext[size];
    memset(plaintext, '\0', size);

    /* Inicialização da chave e do IV. */
    // uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    //                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = dhStorage->getSessionKey();
    }

    // uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = dhStorage->getSessionKey();
    }

    /* Converte o array de char (message) para uint8_t. */
    CharToUint8_t(message, plaintext, size);

    /* Encripta a mensagem utilizando a chave e o iv declarados anteriormente. */
    uint8_t *encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    string result = Uint8_tToHexString(encrypted, size);

    // delete[] encrypted;

    return result;
}
