#include "verbose_client.h"

void send_syn_verbose(char *nonceA)
{
    cout << "Step 1.1" << endl;
    cout << "*********** SEND SYN **************************************************" << endl;
    cout << "nA: " << nonceA << " (gen)" << endl;
    cout << "***********************************************************************\n"   << endl;
}

void recv_ack_verbose(char *nonceB, int sequence, char *serverIP, char *clientIP, bool isNonceTrue)
{
    cout << "Step 2.2" << endl;
    cout << "*********** RECV ACK **************************************************" << endl;
    cout << "nB: " << nonceB << " (stored)" << endl;
    cout << "Sequence: " << sequence << endl;
    cout << "Server IP: " << serverIP << endl;
    cout << "Client IP: " << clientIP << endl;
    cout << "Is Nonce True? " << isNonceTrue << endl;
    cout << "***********************************************************************\n"   << endl;
}

void send_rsa_verbose(RSAStorage *rsaStorage, int sequence, char *nonceA)
{
    cout << "Step 3.1" << endl;
    cout << "************ SEND RSA *************************************************" << endl;
    cout << "Generated RSA Key: {(" << rsaStorage->getMyPublicKey()->d
         << ", " << rsaStorage->getMyPublicKey()->n << "), ("
         << rsaStorage->getMyPrivateKey()->d << ", "
         << rsaStorage->getMyPrivateKey()->n << ")}" << endl;
    cout << "My FDR: " << rsaStorage->getMyFDR()->toString() << endl;
    cout << "Sequence: " << sequence << endl;
    cout << "nA: " << nonceA << " (gen)" << endl;
    cout << "***********************************************************************\n" << endl;
}

void recv_rsa_verbose(RSAStorage *rsaStorage, char *nonceB, bool isHashValid, bool isNonceTrue, bool isAnswerCorrect)
{
    cout << "Step 4.2" << endl;
        cout << "************ RECV RSA *************************************************" << endl;
        cout << "Server Public Key: (" << rsaStorage->getPartnerPublicKey()->d
                << ", " << rsaStorage->getPartnerPublicKey()->n << ")" << endl;
        cout << "nB: " << nonceB << " (stored)" << endl;
        cout << "Is Hash Valid? " << isHashValid << endl;
        cout << "Is Nonce True? " << isNonceTrue << endl;
        cout << "Is Answer Correct? " << isAnswerCorrect << endl;
        cout << "***********************************************************************\n" << endl;
}

void send_rsa_ack_verbose(int sequence, char *nonceA)
{
    cout << "Step 5.1" << endl;
    cout << "************ SEND ACK RSA *********************************************" << endl;
    cout << "Sequence: " << sequence << endl;
    cout << "nA: " << nonceA << " (gen)" << endl << endl << endl;
    cout << "***********************************************************************\n" << endl;

}

void time_limit_burst_verbose()
{
        cout << "*** TIME LIMIT BURST ***" << endl;
}

void recv_dh_verbose(DiffieHellmanPackage *dhPackage, bool isHashValid, bool isNonceTrue)
{
    cout << "Step 6.2" << endl;
    cout << "************ RECV DH **************************************************" << endl;
    cout << "Result: " << dhPackage->getResult() << endl;
    cout << "g: " << dhPackage->getBase() << endl;
    cout << "p: " << dhPackage->getModulus() << endl;
    cout << "nB: " << dhPackage->getNonceB() << " (stored)" << endl;
    cout << "IV: " << dhPackage->getIV() << endl;
    cout << "Is Hash Valid? " << isHashValid << endl;
    cout << "Is Nonce True? " << isNonceTrue << endl;
    cout << "***********************************************************************\n" << endl;
}

void send_dh_verbose(DiffieHellmanPackage *dhPackage, int sessionKey, int sequence, double tp)
{
        cout << "Step 7.1" << endl;
        cout << "************ SEND DH **************************************************" << endl;
        cout << "Session Key: " << sessionKey << endl;
        cout << "Sequence: " << sequence << endl;
        cout << "nA: " << dhPackage->getNonceB() << " (gen)" << endl;
        cout << "tp: " << tp << " ms" << endl;
        cout << "***********************************************************************\n" << endl;
}

void send_dh_ack_verbose(string& nonce, bool isNonceTrue)
{
        cout << "Step 8.2" << endl;
        cout << "************ RECV DH ACK **********************************************" << endl;
        cout << "ACK" << endl;
        cout << "nA: " << nonce << endl;
        cout << "isNonceTrue? " << isNonceTrue << endl;
        cout << "***********************************************************************\n" << endl;
}

void rft_verbose()
{
        cout << "***********************************************************************"   << endl;
        cout << "Request for termination received." << endl;
        cout << "DONE ACK sent." << endl;
        cout << "End of connection." << endl << endl << endl;
        cout << "***********************************************************************\n"   << endl;
}

void wdc_verbose()
{
        cout << "***********************************************************************" << endl;
        cout << "End of connection." << endl;
        cout << "***********************************************************************\n" << endl;
}

void done_verbose()
{
        cout << "\n***********************************************************************" << endl;
        cout << "Send DONE to Server." << endl;
        cout << "***********************************************************************\n" << endl;    
}

void dt_verbose1()
{
    cout << "Envio de dados criptografados com AES." << endl << endl;
    cout << "########## Escreva uma mensagem para o servidor ##########" << endl;
    cout << "------------- Linha em branco para finalizar -------------" << endl;
}


void dt_verbose2(string *sent)
{
    cout << "Sent" << endl << *sent << endl << endl;
}

void response_timeout_verbose()
{
        cout << "***********************************************************************" << endl;
        cout << "Exhausted response time." << endl;
        cout << "***********************************************************************\n" << endl; 
}

void reply_verbose(status s)
{
        cout << "***********************************************************************" << endl;
        cout << "Erro: ";
        
        switch (s)
        {
                case OK:
                        cout << "OK" << endl;
                        break;
                case DENIED:
                        cout << "DENIED" << endl;
                        break;
                case TIMEOUT:
                        cout << "TIMEOUT" << endl;
                        break;
                case NO_REPLY:
                        cout << "NO_REPLY" << endl;
                        break;
                case NONCE_INVALID:
                        cout << "NONCE_INVALID" << endl;
                        break;
                case FDR_INVALID:
                        cout << "FDR_INVALID" << endl;
                        break;
                case HASH_INVALID:
                        cout << "HASH_INVALID" << endl;
                        break;
                case FINISHED:
                        cout << "FINISHED" << endl;
                        break;
                case NOT_CONNECTED:
                        cout << "NOT_CONNECTED" << endl;
                        break;
        }

        cout << "***********************************************************************\n" << endl; 
}

void status_verbose(status s)
{
        switch (s)
        {
                case OK:
                        cout << "OK" << endl;
                        break;
                case DENIED:
                        cout << "DENIED" << endl;
                        break;
                case TIMEOUT:
                        cout << "TIMEOUT" << endl;
                        break;
                case NO_REPLY:
                        cout << "NO_REPLY" << endl;
                        break;
                case NONCE_INVALID:
                        cout << "NONCE_INVALID" << endl;
                        break;
                case FDR_INVALID:
                        cout << "FDR_INVALID" << endl;
                        break;
                case HASH_INVALID:
                        cout << "HASH_INVALID" << endl;
                        break;
                case FINISHED:
                        cout << "FINISHED" << endl;
                        break;
                case NOT_CONNECTED:
                        cout << "NOT_CONNECTED" << endl;
                        break;
        }
}