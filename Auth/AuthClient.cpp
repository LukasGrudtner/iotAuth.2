#include "AuthClient.h"

AuthClient::AuthClient()
{
    nonceA[128] = '\0';
    nonceB[128] = '\0';
    memset(envia, 0, sizeof(envia));
    memset(recebe, 0, sizeof(recebe));
}

// double tp1, tp2, tp3, tp4, tp5, tp6, tp7, tp8;
// double ts1, ts2, ts3, ts4, ts5, ts6, ts7, ts8;

/*  Inicia conexão com o Servidor. */
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
    catch (status e)
    {
        reply_verbose(e);
        return e;
    }

    delete rsaStorage;
    return OK;
}

/*  Entra em estado de espera por dados vindos do Servidor. */
string AuthClient::listen()
{
    if (isConnected())
    {
        /********************* Recebimento dos Dados Cifrados *********************/
        char message[1333];
        memset(message, '\0', sizeof(message));
        int recv = 0;

        while (recv <= 0)
        {
            recv = recvfrom(soc.socket, message, sizeof(message) - 1, 0, soc.server, &soc.size);
        }

        if (isDisconnectRequest(message))
        {
            rdisconnect();
        }
        else
        {
            /**************** RECEBE A MENSAGEM *****************************************/
            /* Converte o array de chars (buffer) em uma string. */
            string encryptedMessage(message);

            /* Inicialização dos vetores ciphertext. */
            char ciphertextChar[encryptedMessage.length()];
            uint8_t ciphertext[encryptedMessage.length()];
            memset(ciphertext, '\0', encryptedMessage.length());

            /* Inicialização do vetor plaintext. */
            uint8_t plaintext[encryptedMessage.length()];
            memset(plaintext, '\0', encryptedMessage.length());

            /* Inicialização da chave e iv. */
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

            /* Converte a mensagem recebida (HEXA) para o array de char ciphertextChar. */
            HexStringToCharArray(&encryptedMessage, encryptedMessage.length(), ciphertextChar);

            /* Converte ciphertextChar em um array de uint8_t (ciphertext). */
            CharToUint8_t(ciphertextChar, ciphertext, encryptedMessage.length());

            /* Decifra a mensagem em um vetor de uint8_t. */
            uint8_t *decrypted = iotAuth.decryptAES(ciphertext, key, iv, encryptedMessage.length());
            // cout << "Decrypted: " << decrypted << endl << endl;

            /************************** ENVIA ACK CONFIRMANDO ********************************/
            while (sack() == false)
                ;

            return Uint8_tToString(decrypted, encryptedMessage.length());
        }
    }
}

string AuthClient::decryptMessage(char *message)
{
    string encryptedMessage(message);

    /* Inicialização dos vetores ciphertext. */
    char ciphertextChar[encryptedMessage.length()];
    uint8_t ciphertext[encryptedMessage.length()];
    memset(ciphertext, '\0', encryptedMessage.length());

    /* Inicialização do vetor plaintext. */
    uint8_t plaintext[encryptedMessage.length()];
    memset(plaintext, 0, encryptedMessage.length());

    /* Inicialização da chave e iv. */
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

    /* Converte a mensagem recebida (HEXA) para o array de char ciphertextChar. */
    HexStringToCharArray(&encryptedMessage, encryptedMessage.length(), ciphertextChar);

    /* Converte ciphertextChar em um array de uint8_t (ciphertext). */
    CharToUint8_t(ciphertextChar, ciphertext, encryptedMessage.length());

    /* Decifra a mensagem em um vetor de uint8_t. */
    uint8_t *decrypted = iotAuth.decryptAES(ciphertext, key, iv, encryptedMessage.length());

    return Uint8_tToString(decrypted, 130);
}

/*  Envia dados para o Servidor. */
int AuthClient::publish(char *data)
{
    if (isConnected())
    {
        string encrypted = encryptMessage(data, 250);

        // cout << "Encrypted Message: " << encrypted << endl;

        int sent = sendto(soc.socket, encrypted.c_str(), encrypted.length(), 0, soc.server, soc.size);

        if (sent > 0)
        {
            if (rack())
            {
                return OK;
            }
            return DENIED;
        }
        else
            return DENIED;
    }
    else
    {
        cout << "Não existe conexão com o servidor!" << endl;
        return NOT_CONNECTED;
    }
    return DENIED;
}

/*  Envia um pedido de término de conexão ao Servidor. */
status AuthClient::disconnect()
{
    if (isConnected())
    {
        return done();
    }
    else
    {
        cout << "Não existe conexão com o servidor!" << endl;
        return NOT_CONNECTED;
    }
}

/*  Retorna um boolean para indicar se possui conexão com o Servidor. */
bool AuthClient::isConnected()
{
    return connected;
}

/*  Step 1
    Envia pedido de início de conexão ao Servidor.   
*/
void AuthClient::send_syn()
{
    // double p1 = currentTime();
    /******************** Init Sequence ********************/
    sequence = iotAuth.randomNumber(9999);

    // double mp1 = currentTime();

    /******************** Generate Nonce ********************/
    // double n1 = currentTime();
    generateNonce(nonceA);
    // double n2 = currentTime();
    // cout << "TIME NONCE (s1 and s2): " << elapsedTime(n1, n2) << "ms." << endl;

    /******************** Mount SYN Package ********************/
    structSyn toSend;
    strncpy(toSend.nonce, nonceA, sizeof(toSend.nonce));

    // double mp2 = currentTime();
    // cout << "TIME MOUNT PACK (s1 and s2): " << elapsedTime(mp1, mp2) << "ms." << endl;

    /******************** Start Network Time ********************/
    t1 = currentTime();

    // double p2 = currentTime();
    // tp1 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s1): " << tp1 << "ms." << endl;

    // ts1 = currentTime();
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

    // double p1 = currentTime();
    // ts2 = currentTime();
    // cout << "TIME TOTAL SENT (s1 and s2): " << elapsedTime(ts1, ts2) << "ms." << endl;

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
        double v1 = currentTime();
        const bool isNonceTrue = (strcmp(received.nonceA, nonceA) == 0);
        double v2 = currentTime();
        cout << "TIME VERIFICATION (s1 and s2): " << elapsedTime(v1, v2) << "ms." << endl;

        /******************** Verbose ********************/
        if (VERBOSE)
            recv_ack_verbose(nonceB, sequence, serverIP, clientIP, isNonceTrue);

        if (isNonceTrue)
        {
            // double p2 = currentTime();
            // tp2 = elapsedTime(p1, p2);
            // cout << "TIME PROCESS (s2): " << tp2 << "ms." << endl;
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
    // double p1 = currentTime();
    // double mp1 = currentTime();
    /******************** Generate RSA/FDR ********************/
    rsaStorage = new RSAStorage();
    rsaStorage->setKeyPair(iotAuth.generateRSAKeyPair());
    rsaStorage->setMyFDR(iotAuth.generateFDR());

    /******************** Generate Nonce ********************/
    // double n1 = currentTime();
    generateNonce(nonceA);
    // double n2 = currentTime();
    // cout << "TIME NONCE (s3 and s4): " << elapsedTime(n1, n2) << "ms." << endl;
    /******************** Mount Package ********************/
    RSAPackage rsaSent;
    rsaSent.setPublicKey(*rsaStorage->getMyPublicKey());
    rsaSent.setFDR(*rsaStorage->getMyFDR());
    rsaSent.setNonceA(nonceA);
    rsaSent.setNonceB(nonceB);

    /******************** Get Hash ********************/
    // double s1 = currentTime();
    string rsaString = rsaSent.toString();
    int *const encryptedHash = iotAuth.signedHash(&rsaString, rsaStorage->getMyPrivateKey());
    // double s2 = currentTime();
    // cout << "TIME SIGNATURE (s3 and s4): " << elapsedTime(s1, s2) << "ms." << endl;

    /******************** Stop Processing Time ********************/
    t2 = currentTime();
    processingTime1 = elapsedTime(t1, t2);

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);
    rsaExchange.setProcessingTime(processingTime1);

    // double mp2 = currentTime();
    // cout << "TIME MOUNT PACK (s3 and s4): " << elapsedTime(mp1, mp2) << "ms." << endl;
    /******************** Start Total Time ********************/
    t1 = currentTime();

    // double p2 = currentTime();
    // tp3 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s3): " << tp3 << "ms." << endl;

    // ts3 = currentTime();
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

    // double p1 = currentTime();
    // ts4 = currentTime();
    // cout << "TIME TOTAL SENT (s3 and s4): " << elapsedTime(ts3, ts4) << "ms." << endl;

    if (recv > 0)
    {
        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        if (isDisconnectRequest(rsaKeyExchange))
        {
            rdisconnect();
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
                double v1 = currentTime();
                const bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
                const bool isNonceTrue = strcmp(rsaPackage->getNonceA(), nonceA) == 0;
                const bool isAnswerCorrect = iotAuth.isAnswerCorrect(rsaStorage->getMyFDR(), rsaStorage->getMyPublicKey()->d, rsaPackage->getAnswerFDR());
                double v2 = currentTime();
                cout << "TIME VERIFICATION (s3 and s4): " << elapsedTime(v1, v2) << "ms." << endl;

                if (VERBOSE)
                    recv_rsa_verbose(rsaStorage, nonceB, isHashValid, isNonceTrue, isAnswerCorrect);

                if (isHashValid && isNonceTrue && isAnswerCorrect)
                {
                    // double p2 = currentTime();
                    // tp4 = elapsedTime(p1, p2);
                    // cout << "TIME PROCESS (s4): " << tp4 << "ms." << endl;
                    send_rsa_ack();
                }
                else if (!isHashValid)
                {
                    done();
                    throw HASH_INVALID;
                }
                else if (!isNonceTrue)
                {
                    done();
                    throw NONCE_INVALID;
                }
                else
                {
                    done();
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
    // double p1 = currentTime();
    // double mp1 = currentTime();
    /******************** Get Answer FDR ********************/
    const int answerFdr = rsaStorage->getPartnerFDR()->getValue(rsaStorage->getPartnerPublicKey()->d);

    /******************** Generate Nonce ********************/
    // double n1 = currentTime();
    generateNonce(nonceA);
    // double n2 = currentTime();
    // cout << "TIME NONCE (s5 and s6): " << elapsedTime(n1, n2) << "ms." << endl;

    /******************** Mount Package ********************/
    RSAPackage rsaSent;
    rsaSent.setNonceA(nonceA);
    rsaSent.setNonceB(nonceB);
    rsaSent.setAnswerFDR(answerFdr);
    rsaSent.setACK();

    /******************** Get Hash ********************/
    // double s1 = currentTime();
    string rsaString = rsaSent.toString();
    int *const encryptedHash = iotAuth.signedHash(&rsaString, rsaStorage->getMyPrivateKey());
    // double s2 = currentTime();
    // cout << "TIME SIGNATURE (s5 and s6): " << elapsedTime(s1, s2) << "ms." << endl;

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);

    // double mp2 = currentTime();
    // cout << "TIME MOUNT PACK (s5 and s6): " << elapsedTime(mp1, mp2) << "ms." << endl;
    /******************** Start Total Time ********************/
    t1 = currentTime();

    // double p2 = currentTime();
    // tp5 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s5): " << tp5 << "ms." << endl;

    // ts5 = currentTime();
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
    // double p1 = currentTime();

    // ts6 = currentTime();
    // cout << "TIME TOTAL SENT (s5 and s6): " << elapsedTime(ts5, ts6) << "ms." << endl;

    if (recv > 0)
    {
        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        if (isDisconnectRequest(encPacket))
        {
            rdisconnect();
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
                double v1 = currentTime();
                const bool isHashValid = iotAuth.isHashValid(&dhString, &decryptedHash);
                const bool isNonceTrue = strcmp(dhPackage.getNonceA(), nonceA) == 0;
                double v2 = currentTime();
                cout << "TIME VERIFICATION (s5 and s6): " << elapsedTime(v1, v2) << "ms." << endl;

                if (VERBOSE)
                    recv_dh_verbose(&dhPackage, isHashValid, isNonceTrue);

                if (isHashValid && isNonceTrue)
                {
                    /******************** Store Nounce B ********************/
                    storeNonceB(dhPackage.getNonceB());
                    /******************** Store DH Package ********************/
                    storeDiffieHellman(&dhPackage);

                    // double p2 = currentTime();
                    // tp6 = elapsedTime(p1, p2);
                    // cout << "TIME PROCESS (s6): " << tp6 << "ms." << endl;

                    send_dh();
                }
                else if (!isHashValid)
                {
                    done();
                    throw HASH_INVALID;
                }
                else
                {
                    done();
                    throw NONCE_INVALID;
                }
            }
            else
            {
                if (VERBOSE)
                    time_limit_burst_verbose();
                done();
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
    // double p1 = currentTime();
    // double mp1 = currentTime();
    /***************** Calculate DH ******************/
    const int sessionKey = dhStorage->calculateSessionKey(dhStorage->getSessionKey());
    const int result = dhStorage->calculateResult();
    dhStorage->setSessionKey(sessionKey);

    /***************** Generate Nonce A ******************/
    // double n1 = currentTime();
    generateNonce(nonceA);
    // double n2 = currentTime();
    // cout << "TIME NONCE (s7 and s8): " << elapsedTime(n1, n2) << "ms." << endl;

    /***************** Mount Package ******************/
    DiffieHellmanPackage diffieHellmanPackage;
    diffieHellmanPackage.setResult(result);
    diffieHellmanPackage.setNonceA(nonceA);
    diffieHellmanPackage.setNonceB(nonceB);

    /***************** Encrypt Hash ******************/
    // double s1 = currentTime();
    string dhString = diffieHellmanPackage.toString();
    int *const encryptedHash = iotAuth.signedHash(&dhString, rsaStorage->getMyPrivateKey());
    // double s2 = currentTime();
    // cout << "TIME SIGNATURE (s7 and s8): " << elapsedTime(s1, s2) << "ms." << endl;

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
    // double e1 = currentTime();
    int *const encryptedExchange = iotAuth.encryptRSA(exchangeBytes, rsaStorage->getPartnerPublicKey(), sizeof(RSAKeyExchange));
    // double e2 = currentTime();
    // cout << "TIME ENCRYPTION (s7 and s8): " << elapsedTime(e1, e2) << "ms." << endl;
    /********************** Mount Enc Packet **********************/
    DHEncPacket encPacket;
    encPacket.setEncryptedExchange(encryptedExchange);
    encPacket.setTP(processingTime2);

    // double mp2 = currentTime();
    // cout << "TIME MOUNT PACK (s7 and s8): " << elapsedTime(mp1, mp2) << "ms." << endl;
    /******************** Start Total Time ********************/
    t1 = currentTime();

    // double p2 = currentTime();
    // tp7 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s7): " << tp7 << "ms." << endl;

    // ts7 = currentTime();
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
    char encrypted[257];
    memset(encrypted, '\0', sizeof(encrypted));

    int recv = recvfrom(soc.socket, encrypted, sizeof(encrypted) - 1, 0, soc.server, &soc.size);
    // double p1 = currentTime();

    // ts8 = currentTime();
    // cout << "TIME TOTAL SENT (s7 and s8): " << elapsedTime(ts7, ts8) << "ms." << endl;

    if (recv > 0)
    {
        /******************** Stop Total Time ********************/
        t2 = currentTime();
        totalTime = elapsedTime(t1, t2);

        if (isDisconnectRequest(encrypted))
        {
            rdisconnect();
        }
        else
        {
            /******************** Proof of Time ********************/
            const double limit = processingTime2 + networkTime + (processingTime2 + networkTime) * 0.1;

            if (totalTime <= limit)
            {
                string ack = decryptMessage(encrypted);
                ack.pop_back();
                ack.pop_back();

                /******************** Validity ********************/
                double v1 = currentTime();
                const bool isNonceTrue = (ack == nonceA);
                double v2 = currentTime();
                cout << "TIME VERIFICATION (s7 and s8): " << elapsedTime(v1, v2) << "ms." << endl;

                if (isNonceTrue)
                {
                    connected = true;
                    // double p2 = currentTime();
                    // tp8 += elapsedTime(p1, p2);
                    // cout << "TIME PROCESS (s8): " << tp8 << "ms." << endl;
                }
                else
                {
                    done();
                    throw NONCE_INVALID;
                }

                /******************** Verbose ********************/
                if (VERBOSE)
                    send_dh_ack_verbose(ack, isNonceTrue);
            }
            else
            {
                if (VERBOSE)
                    time_limit_burst_verbose();
                done();
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

/*  Waiting Done Confirmation
    Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
    fim de conexão enviado pelo Servidor (DONE_ACK).
*/
status AuthClient::wdc()
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
            close(soc.socket);
            return OK;
        }
        else
        {
            connected = false;
            close(soc.socket);
            return DENIED;
        }
    }
    else
    {
        connected = false;
        close(soc.socket);
        return NO_REPLY;
    }
}

/*  Receive Disconnect
    Envia uma confirmação (DONE_ACK) para o pedido de término de conexão
    vindo do Servidor.
*/
void AuthClient::rdisconnect()
{
    int sent = 0;

    do
    {
        sent = sendto(soc.socket, DONE_ACK, strlen(DONE_ACK), 0, soc.server, soc.size);
    } while (sent <= 0);

    connected = false;

    if (VERBOSE)
        rft_verbose();

    close(soc.socket);
}

/*  Envia um pedido de fim de conexão para o cliente. */
status AuthClient::done()
{
    int sent = 0;

    do
    {
        sent = sendto(soc.socket, DONE_MESSAGE, sizeof(DONE_MESSAGE), 0, soc.server, soc.size);
    } while (sent <= 0);

    if (VERBOSE)
        done_verbose();

    return wdc();
}

/*  Envia ACK confirmando o recebimento da publicação. */
bool AuthClient::sack()
{
    char ack = ACK_CHAR;
    uint8_t sent = sendto(soc.socket, &ack, sizeof(ack), 0, soc.server, soc.size);

    if (send > 0)
    {
        return true;
    }
    return false;
}

/*  Recebe ACK confirmando o recebimento da publicação. */
bool AuthClient::rack()
{
    int count = COUNT;
    char ack = 'a';
    int recv;

    while ((recv <= 0 || ack != ACK_CHAR) && count--)
    {
        recv = recvfrom(soc.socket, &ack, sizeof(ack), 0, soc.server, &soc.size);
    }

    if (ack == ACK)
    {
        return true;
    }
    return false;
}

/*  Verifica se a mensagem recebida é um pedido de desconexão. */
template <typename T>
bool AuthClient::isDisconnectRequest(T &object)
{
    int cmp = memcmp(&object, DONE_MESSAGE, strlen(DONE_MESSAGE));
    return cmp == 0;
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

/*  Store Diffie-Hellman
    Armazena os valores pertinentes a troca de chaves Diffie-Hellman:
    expoente, base, módulo, resultado e a chave de sessão.
*/
void AuthClient::storeDiffieHellman(DiffieHellmanPackage *dhPackage)
{
    dhStorage = new DHStorage();

    dhStorage->setExponent(iotAuth.randomNumber(3) + 2);
    dhStorage->setBase(dhPackage->getBase());
    dhStorage->setModulus(dhPackage->getModulus());
    dhStorage->setSessionKey(dhPackage->getResult());
    dhStorage->setIV(dhPackage->getIV());
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

/*  Generate Nonce
    Gera um novo nonce, incrementando o valor de sequência.
*/
void AuthClient::generateNonce(char *nonce)
{
    string message = stringTime() + *clientIP + *serverIP + to_string(sequence++);
    string hash = iotAuth.hash(&message);

    memset(nonce, '\0', 129);
    strncpy(nonce, hash.c_str(), 128);
}

/*  Armazena o valor do nonce B em uma variável global. */
void AuthClient::storeNonceB(char *nonce)
{
    strncpy(nonceB, nonce, sizeof(nonceB));
}