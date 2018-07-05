#include "AuthServer.h"

AuthServer::AuthServer()
{
    memset(buffer, 0, sizeof(buffer));
}


// double tp1, tp2, tp3, tp4, tp5, tp6, tp7, tp8;
// double ts2, ts3, ts4, ts5, ts6, ts7;

/*  Aguarda conexão com algum Cliente. */
bool AuthServer::wait_connection()
{
    if (!isConnected()) 
    {
        connect();
        return true;
    }
    return false;
}




/*  Entra em estado de espera por dados vindos do Cliente. */
string AuthServer::listen()
{
    if (isConnected())
    {
        /********************* Recebimento dos Dados Cifrados *********************/
        char message[500];
        memset(message, '\0', sizeof(message));
        int recv = 0;
        int count = COUNT;

        while (recv <= 0 && count--)
        {
            recv = recvfrom(soc.socket, message, sizeof(message) - 1, 0, soc.client, &soc.size);
        }

        if (count == 0)
        {
            throw TIMEOUT;
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
                key[i] = diffieHellmanStorage->getSessionKey();
            }

            uint8_t iv[16];
            for (int i = 0; i < 16; i++)
            {
                iv[i] = diffieHellmanStorage->getIV();
            }

            /* Converte a mensagem recebida (HEXA) para o array de char ciphertextChar. */
            HexStringToCharArray(&encryptedMessage, encryptedMessage.length(), ciphertextChar);

            /* Converte ciphertextChar em um array de uint8_t (ciphertext). */
            CharToUint8_t(ciphertextChar, ciphertext, encryptedMessage.length());

            /* Decifra a mensagem em um vetor de uint8_t. */
            uint8_t *decrypted = iotAuth.decryptAES(ciphertext, key, iv, encryptedMessage.length());
            // cout << "Decrypted: " << decrypted << endl << endl;

            /************************** ENVIA ACK CONFIRMANDO ********************************/
            while (sack() == false);

            return Uint8_tToString(decrypted, encryptedMessage.length());
        }
    }
}




/*  Envia dados para o Cliente. */
status AuthServer::publish(char *data)
{
    if (isConnected()) {
        string encrypted = encryptMessage(data, 666);

        // cout << "Encrypted Message: " << encrypted << endl;
        
        int sent = sendto(soc.socket, encrypted.c_str(), encrypted.length(), 0, soc.client, soc.size);

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
    } else {
        cout << "Não existe conexão com o servidor!" << endl;
        return NOT_CONNECTED;
    }
    return DENIED;
}




/*  Envia um pedido de término de conexão ao Cliente. */
status AuthServer::disconnect()
{
    if (isConnected())
    {
        return done();
    }
    else
    {
        cout << "Não existe conexão com o cliente!" << endl;
        return NOT_CONNECTED;
    }
}




/*  Retorna um boolean para indicar se possui conexão com o Cliente. */
bool AuthServer::isConnected()
{
    return connected;
}




/*  Step 1
    Recebe um pedido de início de conexão por parte do Cliente.
*/
void AuthServer::recv_syn()
{
    structSyn received;
    
    int recv = 0;

    while (recv <= 0)
    {
        recv = recvfrom(soc.socket, &received, sizeof(syn), 0, soc.client, &soc.size);
    }
    // double p1 = currentTime();

    start = currentTime();

    /* Verifica se a mensagem recebida é um SYN. */
    if (received.message == SYN)
    {
        /******************** Store Nonce A ********************/
        storeNonceA(received.nonce);

        /******************** Verbose ********************/
        if (VERBOSE)
            recv_syn_verbose(nonceA);

        // double p2 = currentTime();
        // tp1 = elapsedTime(p1, p2);
        // cout << "TIME PROCESS (s1): " << tp1 << "ms." << endl;
        send_ack();
    }
    else
    {
        throw DENIED;
    }
}




/*  Step 2
    Envia confirmação ao Cliente referente ao pedido de início de conexão.
*/
void AuthServer::send_ack()
{
    // double p1 = currentTime();
    /******************** Init Sequence ********************/
    sequence = iotAuth.randomNumber(9999);

    double mp1 = currentTime();

    /******************** Generate Nounce B ********************/
    // double n1 = currentTime();
    generateNonce(nonceB);
    // double n2 = currentTime();
    // cout << "TIME NONCE (s2 and s3): " << elapsedTime(n1, n2) << "ms." << endl;

    /******************** Mount Package ********************/
    structAck toSend;
    strncpy(toSend.nonceA, nonceA, sizeof(toSend.nonceA));
    strncpy(toSend.nonceB, nonceB, sizeof(toSend.nonceB));

    double mp2 = currentTime();
    cout << "TIME MOUNT PACK (s2 and s3): " << elapsedTime(mp1, mp2) << "ms." << endl;
    /******************** Start Network Time ********************/
    t1 = currentTime();

    // double p2 = currentTime();
    // tp2 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s2): " << tp2 << "ms." << endl;

    // ts2 = currentTime();

    /******************** Send Package ********************/
    sendto(soc.socket, &toSend, sizeof(ack), 0, soc.client, soc.size);

    /******************** Verbose ********************/
    if (VERBOSE)
        send_ack_verbose(nonceB, sequence, serverIP, clientIP);

    recv_rsa();
}




/*  Step 3
    Recebe os dados RSA vindos do Cliente.
*/
void AuthServer::recv_rsa()
{
    /******************** Receive Exchange ********************/
    RSAKeyExchange rsaReceived;
    int recv = recvfrom(soc.socket, &rsaReceived, sizeof(RSAKeyExchange), 0, soc.client, &soc.size);
    
    // ts3 = currentTime();
    // cout << "TIME TOTAL SENT (s2 and s3): " << elapsedTime(ts2, ts3) << "ms." << endl;

    // double p1 = currentTime();

    if (recv > 0)
    {
        if (isDisconnectRequest(rsaReceived))
        {
            rdisconnect();
        }
        else
        {
            /******************** Stop Network Time ********************/
            t2 = currentTime();
            networkTime = elapsedTime(t1, t2);

            /******************** Start Processing Time ********************/
            t1 = currentTime();

            /******************** Store RSA Data ********************/
            RSAPackage rsaPackage = *rsaReceived.getRSAPackage();

            rsaStorage = new RSAStorage();
            rsaStorage->setPartnerPublicKey(rsaPackage.getPublicKey());
            rsaStorage->setPartnerFDR(rsaPackage.getFDR());

            /******************** Decrypt Hash ********************/
            string rsaString = rsaPackage.toString();
            string decryptedHash = decryptHash(rsaReceived.getEncryptedHash());

            /******************** Store TP ********************/
            tp = rsaReceived.getProcessingTime();

            /******************** Store Nonce A ********************/
            storeNonceA(rsaPackage.getNonceA());

            /******************** Validity Hash ********************/
            // double v1 = currentTime();
            bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
            bool isNonceTrue = strcmp(rsaPackage.getNonceB(), nonceB) == 0;
            // double v2 = currentTime();
            // cout << "TIME VERIFICATION (s2 and s3): " << elapsedTime(v1, v2) << "ms." << endl;

            /******************** Verbose ********************/
            if (VERBOSE)
                recv_rsa_verbose(rsaStorage, nonceA, isHashValid, isNonceTrue);

            if (isHashValid && isNonceTrue)
            {
                // double p2 = currentTime();
                // tp3 = elapsedTime(p1, p2);
                // cout << "TIME PROCESS (s3): " << tp3 << "ms." << endl;

                send_rsa();
            }
            else if (!isHashValid)
            {
                disconnect();
                throw HASH_INVALID;
            }
            else
            {
                disconnect();
                throw NONCE_INVALID;
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





/*  Step 4
    Realiza o envio dos dados RSA para o Cliente.
*/
void AuthServer::send_rsa()
{
    // double p1 = currentTime();
    /******************** Start Auxiliar Time ********************/
    t_aux1 = currentTime();

    double mp1 = currentTime();

    /******************** Get Answer FDR ********************/
    int answerFdr = rsaStorage->getPartnerFDR()->getValue(rsaStorage->getPartnerPublicKey()->d);

    /******************** Generate RSA Keys and FDR ********************/
    rsaStorage->setKeyPair(iotAuth.generateRSAKeyPair());
    rsaStorage->setMyFDR(iotAuth.generateFDR());

    /******************** Generate Nonce ********************/
    // double n1 = currentTime();
    generateNonce(nonceB);
    // double n2 = currentTime();
    // cout << "TIME NONCE (s4 and s5): " << elapsedTime(n1, n2) << "ms." << endl;

    /******************** Mount Package ********************/
    RSAPackage rsaSent;
    rsaSent.setPublicKey(*rsaStorage->getMyPublicKey());
    rsaSent.setAnswerFDR(answerFdr);
    rsaSent.setFDR(*rsaStorage->getMyFDR());
    rsaSent.setNonceA(nonceA);
    rsaSent.setNonceB(nonceB);

    /******************** Get Hash ********************/
    // double s1 = currentTime();
    string packageString = rsaSent.toString();
    string hash = iotAuth.hash(&packageString);
    int *const encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), 128);
    // double s2 = currentTime();
    // cout << "TIME SIGNATURE (s4 and s5): " << elapsedTime(s1, s2) << "ms." << endl;

    /******************** Stop Processing Time ********************/
    t2 = currentTime();
    processingTime1 = elapsedTime(t1, t2);

    /******************** Stop Auxiliar Time ********************/
    t_aux2 = currentTime();
    auxiliarTime = elapsedTime(t_aux1, t_aux2);

    /******************** Rectify Network Time ********************/
    networkTime = networkTime - auxiliarTime;

    /******************** Mount Exchange ********************/
    RSAKeyExchange rsaExchange;
    rsaExchange.setRSAPackage(&rsaSent);
    rsaExchange.setEncryptedHash(encryptedHash);
    rsaExchange.setProcessingTime(processingTime1);

    double mp2 = currentTime();
    cout << "TIME MOUNT PACK (s4 and s5): " << elapsedTime(mp1, mp2) << "ms." << endl;
    /******************** Start Total Time ********************/
    t1 = currentTime();

    // double p2 = currentTime();
    // tp4 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s4): " << tp4 << "ms." << endl;

    // ts4 = currentTime();
    /******************** Send Exchange ********************/
    sendto(soc.socket, (RSAKeyExchange *)&rsaExchange, sizeof(RSAKeyExchange), 0, soc.client, soc.size);

    /******************** Memory Release ********************/
    delete[] encryptedHash;

    /******************** Verbose ********************/
    if (VERBOSE)
        send_rsa_verbose(rsaStorage, sequence, nonceB);

    recv_rsa_ack();
}





/*  Step 5
    Recebe confirmação do Cliente referente ao recebimento dos dados RSA.
*/
void AuthServer::recv_rsa_ack()
{
    RSAKeyExchange rsaReceived;
    int recv = recvfrom(soc.socket, &rsaReceived, sizeof(RSAKeyExchange), 0, soc.client, &soc.size);

    // ts5 = currentTime();
    // cout << "TIME TOTAL SENT (s4 and s5): " << elapsedTime(ts4, ts5) << "ms." << endl;

    // double p1 = currentTime();

    if (recv > 0)
    {
        if (isDisconnectRequest(rsaReceived))
        {
            rdisconnect();
        }
        else
        {
            /******************** Stop Total Time ********************/
            t2 = currentTime();
            totalTime = elapsedTime(t1, t2);

            /******************** Proof of Time ********************/
            // double limit = processingTime1 + networkTime + (processingTime1 + networkTime)*0.1;
            double limit = 1000;

            if (totalTime <= limit)
            {
                /******************** Get Package ********************/
                RSAPackage rsaPackage = *rsaReceived.getRSAPackage();

                /******************** Decrypt Hash ********************/
                string rsaString = rsaPackage.toString();
                string decryptedHash = decryptHash(rsaReceived.getEncryptedHash());

                /******************** Store Nonce A ********************/
                storeNonceA(rsaPackage.getNonceA());

                // double v1 = currentTime();
                bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
                bool isNonceTrue = strcmp(rsaPackage.getNonceB(), nonceB) == 0;
                bool isAnswerCorrect = iotAuth.isAnswerCorrect(rsaStorage->getMyFDR(), rsaStorage->getMyPublicKey()->d, rsaPackage.getAnswerFDR());
                // double v2 = currentTime();
                // cout << "TIME VERIFICATION (s4 and s5): " << elapsedTime(v1, v2) << "ms." << endl;

                if (VERBOSE)
                    recv_rsa_ack_verbose(nonceA, isHashValid, isAnswerCorrect, isNonceTrue);

                /******************** Validity ********************/
                if (isHashValid && isNonceTrue && isAnswerCorrect)
                {
                    // double p2 = currentTime();
                    // tp5 = elapsedTime(p1, p2);
                    // cout << "TIME PROCESS (s5): " << tp5 << "ms." << endl;

                    send_dh();
                }
                else if (!isHashValid)
                {
                    disconnect();
                    throw HASH_INVALID;
                }
                else if (!isNonceTrue)
                {
                    disconnect();
                    throw NONCE_INVALID;
                }
                else
                {
                    disconnect();
                    throw FDR_INVALID;
                }
            }
            else
            {
                if (VERBOSE)
                    time_limit_burst_verbose();
                disconnect();
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




/*  Step 6
    Realiza o envio dos dados Diffie-Hellman para o Cliente.
*/
void AuthServer::send_dh()
{
    // double p1 = currentTime();
    /******************** Start Processing Time 2 ********************/
    t_aux1 = currentTime();

    double mp1 = currentTime();

    /******************** Generate Diffie-Hellman ********************/
    generateDiffieHellman();

    /******************** Generate Nonce B ********************/
    // double n1 = currentTime();
    generateNonce(nonceB);
    // double n2 = currentTime();
    // cout << "TIME NONCE (s6 and s7): " << elapsedTime(n1, n2) << "ms." << endl;

    /******************** Generate IV ********************/
    int iv = iotAuth.randomNumber(90);
    diffieHellmanStorage->setIV(iv);

    /***************** Mount Package ******************/
    DiffieHellmanPackage dhPackage;
    dhPackage.setResult(diffieHellmanStorage->calculateResult());
    dhPackage.setBase(diffieHellmanStorage->getBase());
    dhPackage.setModulus(diffieHellmanStorage->getModulus());
    dhPackage.setNonceA(nonceA);
    dhPackage.setNonceB(nonceB);
    dhPackage.setIV(iv);

    /******************** Get Hash ********************/
    // double s1 = currentTime();
    string packageString = dhPackage.toString();
    string hash = iotAuth.hash(&packageString);
    int *const encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());
    // double s2 = currentTime();
    // cout << "TIME SIGNATURE (s6 and s7): " << elapsedTime(s1, s2) << "ms." << endl;
    /******************** Mount Exchange ********************/
    DHKeyExchange dhSent;
    dhSent.setEncryptedHash(encryptedHash);
    dhSent.setDiffieHellmanPackage(dhPackage);

    /********************** Serialization Exchange **********************/
    byte *const dhExchangeBytes = new byte[sizeof(DHKeyExchange)];
    ObjectToBytes(dhSent, dhExchangeBytes, sizeof(DHKeyExchange));

    /******************** Encryption Exchange ********************/
    // double e1 = currentTime();
    int *const encryptedExchange = iotAuth.encryptRSA(dhExchangeBytes, rsaStorage->getPartnerPublicKey(), sizeof(DHKeyExchange));
    // double e2 = currentTime();
    // cout << "TIME ENCRYPTION (s6 and s7): " << elapsedTime(e1, e2) << "ms." << endl;

    delete[] dhExchangeBytes;
    /******************** Stop Processing Time 2 ********************/
    t_aux2 = currentTime();
    processingTime2 = elapsedTime(t1, t2);

    /******************** Mount Enc Packet ********************/
    DHEncPacket encPacket;
    encPacket.setEncryptedExchange(encryptedExchange);

    encPacket.setTP(processingTime2);

    double mp2 = currentTime();
    cout << "TIME MOUNT PACK (s6 and s7): " << elapsedTime(mp1, mp2) << "ms." << endl;
    /******************** Start Total Time ********************/
    t1 = currentTime();

    // double p2 = currentTime();
    // tp6 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s6): " << tp6 << "ms." << endl;

    // ts6 = currentTime();
    /******************** Send Exchange ********************/
    sendto(soc.socket, (DHEncPacket *)&encPacket, sizeof(DHEncPacket), 0, soc.client, soc.size);

    /******************** Verbose ********************/
    if (VERBOSE)
        send_dh_verbose(&dhPackage, sequence, encPacket.getTP());

    /******************** Memory Release ********************/
    delete[] encryptedHash;
    delete[] encryptedExchange;

    recv_dh();
}




/*  Step 7
    Recebe os dados Diffie-Hellman vindos do Cliente.   */
void AuthServer::recv_dh()
{
    /******************** Recv Enc Packet ********************/
    DHEncPacket encPacket;
    int recv = recvfrom(soc.socket, &encPacket, sizeof(DHEncPacket), 0, soc.client, &soc.size);

    // ts7 = currentTime();
    // cout << "TIME TOTAL SENT (s6 and s7): " << elapsedTime(ts6, ts7) << "ms." << endl;

    // double p1 = currentTime();

    if (recv > 0)
    {

        if (isDisconnectRequest(encPacket))
        {
            rdisconnect();
        }
        else
        {
            /******************** Stop Total Time ********************/
            t2 = currentTime();
            totalTime = elapsedTime(t1, t2);

            /******************** Time of Proof ********************/
            // double limit = networkTime + processingTime2*2;
            double limit = 4000;

            if (totalTime <= limit)
            {
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

                // double v1 = currentTime();
                const bool isHashValid = iotAuth.isHashValid(&dhString, &decryptedHash);
                const bool isNonceTrue = strcmp(dhPackage.getNonceB(), nonceB) == 0;
                // double v2 = currentTime();
                // cout << "TIME VERIFICATION (s6 and s7): " << elapsedTime(v1, v2) << "ms." << endl;

                if (isHashValid && isNonceTrue)
                {
                    /******************** Store Nounce A ********************/
                    storeNonceA(dhPackage.getNonceA());
                    /******************** Calculate Session Key ********************/
                    diffieHellmanStorage->setSessionKey(diffieHellmanStorage->calculateSessionKey(dhPackage.getResult()));

                    if (VERBOSE)
                        recv_dh_verbose(&dhPackage, diffieHellmanStorage->getSessionKey(), isHashValid, isNonceTrue);

                    // double p2 = currentTime();
                    // tp7 = elapsedTime(p1, p2);
                    // cout << "TIME PROCESS (s7): " << tp7 << "ms." << endl;

                    send_dh_ack();
                }
                else if (!isHashValid)
                {
                    disconnect();
                    throw HASH_INVALID;
                }
                else
                {
                    disconnect();
                    throw NONCE_INVALID;
                }
            }
            else
            {
                if (VERBOSE)
                    time_limit_burst_verbose();
                disconnect();
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




/*  Step 8
    Envia confirmação para o Cliente referente ao recebimento dos dados Diffie-Hellman.
*/
void AuthServer::send_dh_ack()
{
    // double p1 = currentTime();
    string ack (nonceA);

    string encrypted = encryptMessage(ack.data(), 128);

    // double p2 = currentTime();
    // tp8 = elapsedTime(p1, p2);
    // cout << "TIME PROCESS (s8): " << tp8 << "ms." << endl;

    sendto(soc.socket, encrypted.data(), encrypted.length(), 0, soc.client, soc.size);

    connected = true;
}




/*  Waiting Done Confirmation
    Verifica se a mensagem vinda do Cliente é uma confirmação do pedido de
    fim de conexão enviado pelo Servidor (DONE_ACK).
    Em caso positivo, altera o estado para HELLO, senão, mantém em WDC. 7
*/
status AuthServer::wdc()
{
    char message[2];
    int count = COUNT;
    int recv = 0;

    do {
        recv = recvfrom(soc.socket, message, sizeof(message), 0, soc.client, &soc.size);
    } while (recv <= 0 && count--);

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
    vindo do Cliente, e fecha o socket.
*/
void AuthServer::rdisconnect()
{
    int sent = 0;

    do
    {
        sent = sendto(soc.socket, DONE_ACK, strlen(DONE_ACK), 0, soc.client, soc.size);
    } while (sent <= 0);

    connected = false;

    if (VERBOSE)
        rft_verbose();

    close(soc.socket);
}




/*  Envia um pedido de fim de conexão para o Cliente. */
status AuthServer::done()
{
    int sent = 0;
    
    do
    {
        sent = sendto(soc.socket, DONE_MESSAGE, sizeof(DONE_MESSAGE), 0, soc.client, soc.size);
    } while (sent <= 0);

    if (VERBOSE)
        done_verbose();

    return wdc();
}




/*  Realiza a conexão com o Cliente. */
status AuthServer::connect()
{
    meuSocket = socket(PF_INET, SOCK_DGRAM, 0);
    servidor.sin_family = AF_INET;
    servidor.sin_port = htons(DEFAULT_PORT);
    servidor.sin_addr.s_addr = INADDR_ANY;

    bind(meuSocket, (struct sockaddr *)&servidor, sizeof(struct sockaddr_in));

    tam_cliente = sizeof(struct sockaddr_in);

    /* Set maximum wait time for response */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_MIC;
    setsockopt(meuSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    /* Get IP Address Server */
    struct hostent *server;
    char host_name[256];
    gethostname(host_name, sizeof(host_name));
    server = gethostbyname(host_name);
    serverIP = inet_ntoa(*(struct in_addr *)*server->h_addr_list);

    /* Get IP Address Client */
    struct hostent *client;
    char client_name[256];
    gethostname(client_name, sizeof(client_name));
    client = gethostbyname(client_name);
    clientIP = inet_ntoa(*(struct in_addr *)*client->h_addr_list);

    soc = {meuSocket, (struct sockaddr *)&cliente, tam_cliente};

    try
    {
        recv_syn();
    }
    catch (status e)
    {
        reply_verbose(e);
        return e;
    }

    return OK;
}




/*  Envia ACK confirmando o recebimento da publicação. */
bool AuthServer::sack()
{
    char ack = ACK_CHAR;
    uint8_t sent = sendto(soc.socket, &ack, sizeof(ack), 0, soc.client, soc.size);

    if (send > 0)
    {
        return true;
    }
    return false;
}




/*  Recebe ACK confirmando o recebimento da publicação. */
bool AuthServer::rack()
{
    char ack = 'a';
    int count = COUNT;
    int recv;

    while ((recv <= 0 || ack != ACK_CHAR) && count--)
    {
        recv = recvfrom(soc.socket, &ack, sizeof(ack), 0, soc.client, &soc.size);
    }

    if (ack == ACK)
    {
        return true;
    } 
    return false;
}




/*  Verifica se a mensagem recebida é um pedido de desconexão. */
template <typename T>
bool AuthServer::isDisconnectRequest(T &object)
{
    int cmp = memcmp(&object, DONE_MESSAGE, strlen(DONE_MESSAGE));
    return cmp == 0;
}




/*  Armazena o valor do nonce B em uma variável global. */
void AuthServer::storeNonceA(char *nonce)
{
    strncpy(nonceA, nonce, sizeof(nonceA));
}




/*  Gera um valor para o nonce B.   */
void AuthServer::generateNonce(char *nonce)
{
    string message = stringTime() + *serverIP + *clientIP + to_string(sequence++);
    string hash = iotAuth.hash(&message);

    memset(nonce, '\0', 129);
    strncpy(nonce, hash.c_str(), 128);
}




/*  Decifra o hash utilizando a chave pública do Cliente. */
string AuthServer::decryptHash(int *encryptedHash)
{
    byte *decryptedHash = iotAuth.decryptRSA(encryptedHash, rsaStorage->getPartnerPublicKey(), 128);

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




/*  Inicializa os valores pertinentes a troca de chaves Diffie-Hellman:
    expoente, base, módulo, resultado e a chave de sessão.
*/
void AuthServer::generateDiffieHellman()
{
    diffieHellmanStorage = new DHStorage();
    diffieHellmanStorage->setBase(iotAuth.randomNumber(100) + 2);
    diffieHellmanStorage->setExponent(iotAuth.randomNumber(3) + 2);
    diffieHellmanStorage->setModulus(iotAuth.randomNumber(100) + 2);
}




/*  Cifra a mensagem utilizando o algoritmo AES 256 e a chave de sessão. */
string AuthServer::encryptMessage(char *message, int size)
{
    /* Inicialização do vetor plaintext. */
    uint8_t plaintext[size];
    memset(plaintext, 0, size);

    /* Inicialização da chave e do IV. */
    uint8_t key[32];
    for (int i = 0; i < 32; i++)
    {
        key[i] = diffieHellmanStorage->getSessionKey();
    }

    uint8_t iv[16];
    for (int i = 0; i < 16; i++)
    {
        iv[i] = diffieHellmanStorage->getIV();
    }

    /* Converte o array de char (message) para uint8_t. */
    CharToUint8_t(message, plaintext, size);

    /* Encripta a mensagem utilizando a chave e o iv declarados anteriormente. */
    uint8_t *const encrypted = iotAuth.encryptAES(plaintext, key, iv, size);

    const string result = Uint8_tToHexString(encrypted, size);

    return result;
}