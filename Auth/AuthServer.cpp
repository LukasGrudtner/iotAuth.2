#include "AuthServer.h"

AuthServer::AuthServer()
{
    memset(buffer, 0, sizeof(buffer));
}




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
        char message[1333];
        memset(message, '\0', sizeof(message));
        int recv = 0;
        int count = COUNT;

        while (recv <= 0 && count--)
        {
            recv = soc.recv(message, sizeof(message) - 1);
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
        
        int sent = soc.send(encrypted.c_str(), encrypted.length());

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
        recv = soc.recv(&received, sizeof(syn));
    }

    start = currentTime();

    /* Verifica se a mensagem recebida é um SYN. */
    if (received.message == SYN)
    {
        /******************** Store Nonce A ********************/
        storeNonceA(received.nonce);

        /******************** Verbose ********************/
        if (VERBOSE)
            recv_syn_verbose(nonceA);

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
    /******************** Init Sequence ********************/
    sequence = iotAuth.randomNumber(9999);

    /******************** Generate Nounce B ********************/
    generateNonce(nonceB);

    /******************** Mount Package ********************/
    structAck toSend;
    strncpy(toSend.nonceA, nonceA, sizeof(toSend.nonceA));
    strncpy(toSend.nonceB, nonceB, sizeof(toSend.nonceB));

    /******************** Start Network Time ********************/
    t1 = currentTime();

    /******************** Send Package ********************/
    soc.send(&toSend, sizeof(ack));

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
    int recv = soc.recv(&rsaReceived, sizeof(RSAKeyExchange));

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
            bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
            bool isNonceTrue = strcmp(rsaPackage.getNonceB(), nonceB) == 0;

            /******************** Verbose ********************/
            if (VERBOSE)
                recv_rsa_verbose(rsaStorage, nonceA, isHashValid, isNonceTrue);

            if (isHashValid && isNonceTrue)
            {
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
    /******************** Start Auxiliar Time ********************/
    t_aux1 = currentTime();

    /******************** Get Answer FDR ********************/
    int answerFdr = rsaStorage->getPartnerFDR()->getValue(rsaStorage->getPartnerPublicKey()->d);

    /******************** Generate RSA Keys and FDR ********************/
    rsaStorage->setKeyPair(iotAuth.generateRSAKeyPair());
    rsaStorage->setMyFDR(iotAuth.generateFDR());

    /******************** Generate Nonce ********************/
    generateNonce(nonceB);

    /******************** Mount Package ********************/
    RSAPackage rsaSent;
    rsaSent.setPublicKey(*rsaStorage->getMyPublicKey());
    rsaSent.setAnswerFDR(answerFdr);
    rsaSent.setFDR(*rsaStorage->getMyFDR());
    rsaSent.setNonceA(nonceA);
    rsaSent.setNonceB(nonceB);

    /******************** Get Hash ********************/
    string packageString = rsaSent.toString();
    string hash = iotAuth.hash(&packageString);


    /******************** Encrypt Hash ********************/
    int *const encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), 128);

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

    /******************** Start Total Time ********************/
    t1 = currentTime();

    /******************** Send Exchange ********************/
    soc.send((RSAKeyExchange *)&rsaExchange, sizeof(RSAKeyExchange));

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
    int recv = soc.recv(&rsaReceived, sizeof(RSAKeyExchange));

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
            double limit = processingTime1 + networkTime + (processingTime1 + networkTime)*0.1;
            // double limit = 1000;

            if (totalTime <= limit)
            {
                /******************** Get Package ********************/
                RSAPackage rsaPackage = *rsaReceived.getRSAPackage();

                /******************** Decrypt Hash ********************/
                string rsaString = rsaPackage.toString();
                string decryptedHash = decryptHash(rsaReceived.getEncryptedHash());

                /******************** Store Nonce A ********************/
                storeNonceA(rsaPackage.getNonceA());

                bool isHashValid = iotAuth.isHashValid(&rsaString, &decryptedHash);
                bool isNonceTrue = strcmp(rsaPackage.getNonceB(), nonceB) == 0;
                bool isAnswerCorrect = iotAuth.isAnswerCorrect(rsaStorage->getMyFDR(), rsaStorage->getMyPublicKey()->d, rsaPackage.getAnswerFDR());

                if (VERBOSE)
                    recv_rsa_ack_verbose(nonceA, isHashValid, isAnswerCorrect, isNonceTrue);

                /******************** Validity ********************/
                if (isHashValid && isNonceTrue && isAnswerCorrect)
                {
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
    /******************** Start Processing Time 2 ********************/
    t_aux1 = currentTime();

    /******************** Generate Diffie-Hellman ********************/
    generateDiffieHellman();

    /******************** Generate Nonce B ********************/
    generateNonce(nonceB);

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
    string packageString = dhPackage.toString();
    string hash = iotAuth.hash(&packageString);

    /******************** Encrypt Hash ********************/
    int *const encryptedHash = iotAuth.encryptRSA(&hash, rsaStorage->getMyPrivateKey(), hash.length());

    /******************** Mount Exchange ********************/
    DHKeyExchange dhSent;
    dhSent.setEncryptedHash(encryptedHash);
    dhSent.setDiffieHellmanPackage(dhPackage);

    /********************** Serialization Exchange **********************/
    byte *const dhExchangeBytes = new byte[sizeof(DHKeyExchange)];
    ObjectToBytes(dhSent, dhExchangeBytes, sizeof(DHKeyExchange));

    /******************** Encryption Exchange ********************/
    int *const encryptedExchange = iotAuth.encryptRSA(dhExchangeBytes, rsaStorage->getPartnerPublicKey(), sizeof(DHKeyExchange));
    delete[] dhExchangeBytes;

    /******************** Stop Processing Time 2 ********************/
    t_aux2 = currentTime();
    processingTime2 = elapsedTime(t1, t2);

    /******************** Mount Enc Packet ********************/
    DHEncPacket encPacket;
    encPacket.setEncryptedExchange(encryptedExchange);

    encPacket.setTP(processingTime2);

    /******************** Start Total Time ********************/
    t1 = currentTime();

    /******************** Send Exchange ********************/
    soc.send((DHEncPacket *)&encPacket, sizeof(DHEncPacket));

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
    int recv = soc.recv(&encPacket, sizeof(DHEncPacket));

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
                const bool isHashValid = iotAuth.isHashValid(&dhString, &decryptedHash);
                const bool isNonceTrue = strcmp(dhPackage.getNonceB(), nonceB) == 0;

                if (isHashValid && isNonceTrue)
                {
                    /******************** Store Nounce A ********************/
                    storeNonceA(dhPackage.getNonceA());
                    /******************** Calculate Session Key ********************/
                    diffieHellmanStorage->setSessionKey(diffieHellmanStorage->calculateSessionKey(dhPackage.getResult()));

                    if (VERBOSE)
                        recv_dh_verbose(&dhPackage, diffieHellmanStorage->getSessionKey(), isHashValid, isNonceTrue);

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
    /******************** Mount ACK ********************/
    DH_ACK ack;
    ack.message = ACK;
    strncpy(ack.nonce, nonceA, sizeof(ack.nonce));

    // /******************** Serialize ACK ********************/
    byte *const ackBytes = new byte[sizeof(DH_ACK)];
    ObjectToBytes(ack, ackBytes, sizeof(DH_ACK));

    /******************** Encrypt ACK ********************/
    int *const encryptedAck = iotAuth.encryptRSA(ackBytes, rsaStorage->getMyPrivateKey(), sizeof(DH_ACK));
    delete[] ackBytes;

    /******************** Send ACK ********************/
    soc.send((int *)encryptedAck, sizeof(DH_ACK) * sizeof(int));

    delete[] encryptedAck;

    /******************** Verbose ********************/
    if (VERBOSE)
        send_dh_ack_verbose(&ack);

    connected = true;

    delete rsaStorage;
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
        recv = soc.recv(message, sizeof(message));
    } while (recv <= 0 && count--);

    if (recv > 0)
    {
        if (message[0] == DONE_ACK_CHAR)
        {
            if (VERBOSE)
                wdc_verbose();

            connected = false;
            soc.finish();
            return OK;
        }
        else
        {
            connected = false;
            soc.finish();
            return DENIED;
        }
    }
    else
    {
        connected = false;
        soc.finish();
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
        sent = soc.send(DONE_ACK, strlen(DONE_ACK));
    } while (sent <= 0);

    connected = false;

    if (VERBOSE)
        rft_verbose();

    soc.finish();
}




/*  Envia um pedido de fim de conexão para o Cliente. */
status AuthServer::done()
{
    int sent = 0;
    
    do
    {
        sent = soc.send(DONE_MESSAGE, sizeof(DONE_MESSAGE));
    } while (sent <= 0);

    if (VERBOSE)
        done_verbose();

    return wdc();
}




/*  Realiza a conexão com o Cliente. */
status AuthServer::connect()
{
    soc.connect();

    /* Set maximum wait time for response */
    soc.max_response_time(TIMEOUT_SEC, TIMEOUT_MIC);

    /* Get IP Address Server */
    serverIP = soc.server_address();

    /* Get IP Address Client */
    clientIP = soc.client_address();

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
    uint8_t sent = soc.send(&ack, sizeof(ack));

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
        recv = soc.recv(&ack, sizeof(ack));
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