#include "AuthClient.h"

AuthClient::AuthClient()
{
    nonceA[128] = '\0';
    nonceB[128] = '\0';
    memset(envia, 0, sizeof(envia));
    memset(recebe, 0, sizeof(recebe));
}

/*  Step 1
    Envia pedido de início de conexão ao Servidor.   
*/
void AuthClient::send_syn()
{
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
    sendto(soc.socket, (syn *)&toSend, sizeof(syn), 0, soc.server, soc.size);

    /******************** Verbose ********************/
    if (VERBOSE)
        send_syn_verbose(nonceA);

    recv_ack();
}

/*  Step 2
    Recebe confirmação do Servidor referente ao pedido de início de conexão.    
*/
void AuthClient::recv_ack()
{
    /******************** Receive ACK ********************/
    structAck received;
    int recv = recvfrom(soc.socket, &received, sizeof(ack), 0, soc.server, &soc.size);

    if (recv > 0)
    {
        /******************** Stop Network Time ********************/
        t2 = currentTime();
        networkTime = elapsedTime(t1, t2);

        /******************** Start Processing Time ********************/
        t1 = currentTime();

        /******************** Store Nonce B ********************/
        storeNonceB(received.nonceB);

        /******************** Validity Message ********************/
        const bool isNonceTrue = (strcmp(received.nonceA, nonceA) == 0);

        /******************** Verbose ********************/
        if (VERBOSE)
            recv_ack_verbose(nonceB, sequence, serverIP, clientIP, isNonceTrue);

        if (isNonceTrue)
        {
            send_rsa();
        }
        else
        {
            throw NONCE_INVALID;
        }
    }
    else
    {
        if (VERBOSE)
            response_timeout_verbose();
        throw NO_REPLY;
    }
}

/*  Step 3
    Realiza o envio dos dados RSA para o Servidor.  
*/
void AuthClient::send_rsa()
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
    int *const encryptedHash = iotAuth.signedHash(&rsaString, rsaStorage->getMyPrivateKey());

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
    sendto(soc.socket, (RSAKeyExchange *)&rsaExchange, sizeof(rsaExchange), 0, soc.server, soc.size);

    delete[] encryptedHash;

    /******************** Verbose ********************/
    if (VERBOSE)
        send_rsa_verbose(rsaStorage, sequence, nonceA);

    recv_rsa();
}

/*  Step 4
    Recebe os dados RSA vindos do Servidor.
*/
void AuthClient::recv_rsa()
{
    /******************** Receive Exchange ********************/
    RSAKeyExchange rsaKeyExchange;
    int recv = recvfrom(soc.socket, &rsaKeyExchange, sizeof(RSAKeyExchange), 0, soc.server, &soc.size);

    if (recv > 0)
    {
        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        if (checkRequestForTermination(rsaKeyExchange))
        {
            rft();
        }
        else
        {
            /******************** Proof of Time ********************/
            const double limit = processingTime1 + networkTime + (processingTime1 + networkTime) * 0.1;

            if (totalTime <= 2000)
            {
                /******************** Get Package ********************/
                RSAPackage *const rsaPackage = rsaKeyExchange.getRSAPackage();

                /******************** Config RSA ********************/
                rsaStorage->setPartnerPublicKey(rsaPackage->getPublicKey());
                rsaStorage->setPartnerFDR(rsaPackage->getFDR());
                storeNonceB(rsaPackage->getNonceB());

                /******************** Decrypt Hash ********************/
                string rsaString = rsaPackage->toString();
                string decryptedHash = decryptHash(rsaKeyExchange.getEncryptedHash());

                /******************** Validity ********************/
                const bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
                const bool isNonceTrue = strcmp(rsaPackage->getNonceA(), nonceA) == 0;
                const bool isAnswerCorrect = iotAuth.isAnswerCorrect(rsaStorage->getMyFDR(), rsaStorage->getMyPublicKey()->d, rsaPackage->getAnswerFDR());

                if (VERBOSE)
                    recv_rsa_verbose(rsaStorage, nonceB, isHashValid, isNonceTrue, isAnswerCorrect);

                if (isHashValid && isNonceTrue && isAnswerCorrect)
                {
                    send_rsa_ack();
                }
                else if (!isHashValid)
                {
                    throw HASH_INVALID;
                }
                else if (!isNonceTrue)
                {
                    throw NONCE_INVALID;
                }
                else
                {
                    throw FDR_INVALID;
                }
            }
            else
            {
                if (VERBOSE)
                    time_limit_burst_verbose();
                throw TIMEOUT;
            }
        }
    }
    else
    {
        if (VERBOSE)
            response_timeout_verbose();
        throw NO_REPLY;
    }
}

/*  Step 5
    Envia confirmação para o Servidor referente ao recebimento dos dados RSA.  
*/
void AuthClient::send_rsa_ack()
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
    int *const encryptedHash = iotAuth.signedHash(&rsaString, rsaStorage->getMyPrivateKey());

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);

    /******************** Start Total Time ********************/
    t1 = currentTime();

    /******************** Send Exchange ********************/
    sendto(soc.socket, (RSAKeyExchange *)&rsaExchange, sizeof(rsaExchange), 0, soc.server, soc.size);

    delete[] encryptedHash;

    /******************** Verbose ********************/
    if (VERBOSE)
        send_rsa_ack_verbose(sequence, nonceA);

    recv_dh();
}

/*  Step 6
    Realiza o recebimento dos dados Diffie-Hellman vinda do Servidor.
*/
void AuthClient::recv_dh()
{
    /******************** Recv Enc Packet ********************/
    DHEncPacket encPacket;
    int recv = recvfrom(soc.socket, &encPacket, sizeof(DHEncPacket), 0, soc.server, &soc.size);

    if (recv > 0)
    {
        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        if (checkRequestForTermination(encPacket))
        {
            rft();
        }
        else
        {
            /******************** Time of Proof ********************/
            if (totalTime <= 2000)
            {

                /******************** Start Processing Time 2 ********************/
                t_aux1 = currentTime();

                /******************** Decrypt Exchange ********************/
                DHKeyExchange dhKeyExchange;
                int *const encryptedExchange = encPacket.getEncryptedExchange();
                byte *const dhExchangeBytes = iotAuth.decryptRSA(encryptedExchange, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));

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

                if (VERBOSE)
                    recv_dh_verbose(&dhPackage, isHashValid, isNonceTrue);

                if (isHashValid && isNonceTrue)
                {
                    /******************** Store Nounce B ********************/
                    storeNonceB(dhPackage.getNonceB());
                    /******************** Store DH Package ********************/
                    storeDiffieHellman(&dhPackage);

                    send_dh();
                }
                else if (!isHashValid)
                {
                    throw HASH_INVALID;
                }
                else
                {
                    throw NONCE_INVALID;
                }
            }
            else
            {
                if (VERBOSE)
                    time_limit_burst_verbose();
                throw TIMEOUT;
            }
        }
    }
    else
    {
        if (VERBOSE)
            response_timeout_verbose();
        throw NO_REPLY;
    }
}

/*  Step 7
    Realiza o envio dos dados Diffie-Hellman para o Servidor.
*/
void AuthClient::send_dh()
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
    int *const encryptedHash = iotAuth.signedHash(&dhString, rsaStorage->getMyPrivateKey());

    /***************** Stop Processing Time 2 ******************/
    t2 = currentTime();
    processingTime2 = elapsedTime(t1, t2);

    /********************** Mount Exchange ************************/
    DHKeyExchange dhSent;
    dhSent.setEncryptedHash(encryptedHash);
    dhSent.setDiffieHellmanPackage(diffieHellmanPackage);

    /********************** Serialize Exchange **********************/
    byte *const exchangeBytes = new byte[sizeof(DHKeyExchange)];
    ObjectToBytes(dhSent, exchangeBytes, sizeof(DHKeyExchange));

    /********************** Encrypt Exchange **********************/
    int *const encryptedExchange = iotAuth.encryptRSA(exchangeBytes, rsaStorage->getPartnerPublicKey(), sizeof(RSAKeyExchange));

    /********************** Mount Enc Packet **********************/
    DHEncPacket encPacket;
    encPacket.setEncryptedExchange(encryptedExchange);
    encPacket.setTP(processingTime2);

    /******************** Start Total Time ********************/
    t1 = currentTime();

    /******************** Send Enc Packet ********************/
    sendto(soc.socket, (DHEncPacket *)&encPacket, sizeof(DHEncPacket), 0, soc.server, soc.size);

    /******************** Verbose ********************/
    if (VERBOSE)
        send_dh_verbose(&diffieHellmanPackage, sessionKey, sequence, encPacket.getTP());

    delete[] exchangeBytes;
    delete[] encryptedHash;
    delete[] encryptedExchange;

    recv_dh_ack();
}

/*  Step 8
    Recebe a confirmação do Servidor referente aos dados Diffie-Hellman enviados.
*/
void AuthClient::recv_dh_ack()
{
    /******************** Recv ACK ********************/
    int encryptedACK[sizeof(DH_ACK)];
    int recv = recvfrom(soc.socket, encryptedACK, sizeof(DH_ACK) * sizeof(int), 0, soc.server, &soc.size);

    if (recv > 0)
    {
        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        if (checkRequestForTermination(encryptedACK))
        {
            rft();
        }
        else
        {
            /******************** Proof of Time ********************/
            const double limit = processingTime2 + networkTime + (processingTime2 + networkTime) * 0.1;

            if (totalTime <= limit)
            {
                /******************** Decrypt ACK ********************/
                byte *const decryptedACKBytes = iotAuth.decryptRSA(encryptedACK, rsaStorage->getPartnerPublicKey(), sizeof(DH_ACK));

                /******************** Deserialize ACK ********************/
                DH_ACK ack;
                BytesToObject(decryptedACKBytes, ack, sizeof(DH_ACK));
                delete[] decryptedACKBytes;

                /******************** Validity ********************/
                const bool isNonceTrue = (strcmp(ack.nonce, nonceA) == 0);

                if (isNonceTrue)
                {
                    connected = true;
                    // data_transfer(soc);
                }
                else
                {
                    throw NONCE_INVALID;
                }

                /******************** Verbose ********************/
                if (VERBOSE)
                    send_dh_ack_verbose(&ack, isNonceTrue);
            }
            else
            {
                if (VERBOSE)
                    time_limit_burst_verbose();
                throw TIMEOUT;
            }
        }
    }
    else
    {
        if (VERBOSE)
            response_timeout_verbose();
        throw NO_REPLY;
    }
}

/*  Step 9
    Realiza a transferência de dados cifrados para o Servidor.
*/
void AuthClient::data_transfer()
{
    delete rsaStorage;

    char envia[666];
    memset(envia, '\0', sizeof(envia));

    if (VERBOSE)
    {
        dt_verbose1();
    }

    /* Captura a mensagem digitada no terminal para a criptografia. */
    // fgets(envia, 666, stdin);
    cin >> envia;

    /* Enquanto o usuário não digitar um 'Enter': */
    while (strcmp(envia, "\n") != 0)
    {

        /* Encripta a mensagem digitada pelo usuário. */
        string encryptedMessage = encryptMessage(envia, sizeof(envia));
        if (VERBOSE)
        {
            dt_verbose2(&encryptedMessage);
        }

        /* Converte a string em um array de char. */
        char encryptedMessageChar[encryptedMessage.length()];
        memset(encryptedMessageChar, '\0', sizeof(encryptedMessageChar));
        strncpy(encryptedMessageChar, encryptedMessage.c_str(), sizeof(encryptedMessageChar));

        /* Envia a mensagem cifrada ao Servidor. */
        sendto(soc.socket, encryptedMessageChar, strlen(encryptedMessageChar), 0, soc.server, soc.size);
        memset(envia, '\0', sizeof(envia));
        // fgets(envia, 665, stdin);
        cin >> envia;
    }
}

/*  Armazena o valor do nonce B em uma variável global. */
void AuthClient::storeNonceB(char *nonce)
{
    strncpy(nonceB, nonce, sizeof(nonceB));
}

/***********************************************************************************************/

/*  Waiting Done Confirmation
    Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
    fim de conexão enviado pelo Servidor (DONE_ACK).
    Em caso positivo, altera o estado para HELLO, senão, mantém em WDC.
*/
void AuthClient::wdc()
{
    char message[2];
    int recv = recvfrom(soc.socket, message, sizeof(message), 0, soc.server, &soc.size);

    if (recv > 0)
    {
        if (message[0] == DONE_ACK_CHAR)
        {
            if (VERBOSE)
                wdc_verbose();
            connected = false;
        }
        else
        {
            throw DENIED;
        }
    }
    else
    {
        throw NO_REPLY;
    }
}

/*  Request for Termination
    Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
    vindo do Cliente, e seta o estado para HELLO.
*/
void AuthClient::rft()
{
    sendto(soc.socket, DONE_ACK, strlen(DONE_ACK), 0, soc.server, soc.size);
    connected = false;

    if (VERBOSE)
        rft_verbose();
}

/*  Done
    Envia um pedido de término de conexão ao Cliente, e seta o estado atual
    para WDC (Waiting Done Confirmation).
*/
void AuthClient::done()
{
    sendto(soc.socket, DONE_MESSAGE, sizeof(DONE_MESSAGE), 0, soc.server, soc.size);
    if (VERBOSE)
        done_verbose();

    wdc();
}

void AuthClient::generateNonce(char *nonce)
{
    string message = stringTime() + *clientIP + *serverIP + to_string(sequence++);
    string hash = iotAuth.hash(&message);

    memset(nonce, '\0', 129);
    strncpy(nonce, hash.c_str(), 128);
}

void AuthClient::storeDiffieHellman(DiffieHellmanPackage *dhPackage)
{
    dhStorage = new DHStorage();

    dhStorage->setExponent(iotAuth.randomNumber(3) + 2);
    dhStorage->setBase(dhPackage->getBase());
    dhStorage->setModulus(dhPackage->getModulus());
    dhStorage->setSessionKey(dhPackage->getResult());
    dhStorage->setIV(dhPackage->getIV());
}

/*  Decrypt DH Key Exchange
    Decifra o pacote de troca Diffie-Hellman utilizando a chave privada do Servidor.
    Recebe por parâmetro a mensagem cifrada e retorna por parâmetro o pacote decifrado.
*/
void AuthClient::decryptDHKeyExchange(int *encryptedMessage, DHKeyExchange *dhKeyExchange)
{
    byte *const decryptedMessage = iotAuth.decryptRSA(encryptedMessage, rsaStorage->getMyPrivateKey(), sizeof(DHKeyExchange));

    BytesToObject(decryptedMessage, *dhKeyExchange, sizeof(DHKeyExchange));

    delete[] decryptedMessage;
}

/*  Decrypt Hash
    Decifra o hash obtido do pacote utilizando a chave pública do Cliente.
    Retorna o hash em uma string.
*/
string AuthClient::decryptHash(int *encryptedHash)
{
    byte *const decryptedHash = iotAuth.decryptRSA(encryptedHash, rsaStorage->getPartnerPublicKey(), 128);

    char aux;
    string decryptedHashString = "";
    for (int i = 0; i < 128; i++)
    {
        aux = decryptedHash[i];
        decryptedHashString += aux;
    }

    delete[] decryptedHash;

    return decryptedHashString;
}

/*  Encrypt Message
    Encripta a mensagem utilizando a chave de sessão.
*/
string AuthClient::encryptMessage(char *message, int size)
{
    /* Inicialização do vetor plaintext. */
    uint8_t plaintext[size];
    memset(plaintext, 0, size);

    /* Inicialização da chave e do IV. */
    uint8_t key[32];
    for (int i = 0; i < 32; i++)
    {
        key[i] = dhStorage->getSessionKey();
    }

    uint8_t iv[16];
    for (int i = 0; i < 16; i++)
    {
        iv[i] = dhStorage->getIV();
    }

    /* Converte o array de char (message) para uint8_t. */
    CharToUint8_t(message, plaintext, size);

    /* Encripta a mensagem utilizando a chave e o iv declarados anteriormente. */
    uint8_t *const encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    const string result = Uint8_tToHexString(encrypted, size);

    return result;
}

template <typename T>
bool AuthClient::checkRequestForTermination(T &object)
{
    int cmp = memcmp(&object, DONE_MESSAGE, strlen(DONE_MESSAGE));
    return cmp == 0;
}

int AuthClient::connect(char *address, int port)
{
    if (*address == '\0')
    {
        fprintf(stderr, "ERROR, no such host\n");
        return DENIED;
    }

    server = gethostbyname(address);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        return DENIED;
    }

    bcopy((char *)server->h_addr,
          (char *)&servidor.sin_addr.s_addr,
          server->h_length);

    meuSocket = socket(PF_INET, SOCK_DGRAM, 0);
    servidor.sin_family = AF_INET;   // familia de endereços
    servidor.sin_port = htons(port); // porta

    /* Set maximum wait time for response */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_MIC;
    setsockopt(meuSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    /* Get IP Address Server */
    gethostname(host_name, sizeof(host_name));
    server = gethostbyname(host_name);
    serverIP = inet_ntoa(*(struct in_addr *)*server->h_addr_list);

    /* Get IP Address Client */
    struct hostent *client;
    gethostname(client_name, sizeof(client_name));
    client = gethostbyname(client_name);
    clientIP = inet_ntoa(*(struct in_addr *)*client->h_addr_list);

    soc = {meuSocket, (struct sockaddr *)&servidor, sizeof(struct sockaddr_in)};

    try
    {
        send_syn();
    }
    catch (Reply e)
    {
        reply_verbose(e);
        return e;
    }

    delete rsaStorage;
    return OK;
}

bool AuthClient::isConnected()
{
    return connected;
}

int AuthClient::publish(char *data)
{
    if (isConnected()) {

        cout << "\nPublish: " << data << endl;

        string encrypted = encryptMessage(data, 666);

        cout << "Encrypted Message: " << encrypted << endl;
        
        int sent = sendto(soc.socket, encrypted.c_str(), encrypted.length(), 0, soc.server, soc.size);

        if (sent > 0)
            return OK;
        else
            return DENIED;
    } else {
        cout << "Não existe conexão com o servidor!" << endl;
        return -1;
    }

}