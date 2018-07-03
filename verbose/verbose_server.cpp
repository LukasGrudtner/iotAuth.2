#include "verbose_server.h"

void recv_syn_verbose(char *nonceA)
{
        cout << "Step 1.2" << endl;
    cout << "*********** RECV SYN **************************************************" << endl;
    cout << "nA: " << nonceA << " (stored)" << endl;
    cout << "***********************************************************************\n"   << endl;
}

void send_ack_verbose(char *nonceB, int sequence, char *serverIP, char *clientIP)
{
        cout << "Step 2.1" << endl;
        cout << "*********** SEND ACK **************************************************" << endl;
        cout << "nB: " << nonceB << " (gen)" << endl;
        cout << "Sequence: " << sequence << endl << endl;
        cout << "Server IP: " << serverIP << endl;
        cout << "Client IP: " << clientIP << endl;
        cout << "***********************************************************************\n"   << endl;
}

void recv_rsa_verbose(RSAStorage *rsaStorage, char *nonceA, bool isHashValid, bool isNonceTrue)
{
        cout << "Step 3.2" << endl;
        cout << "************ RECV RSA *************************************************" << endl;
        cout << "Client Public Key: {(" << rsaStorage->getPartnerPublicKey()->d
                << ", " << rsaStorage->getPartnerPublicKey()->n << ")" << endl;
        cout << "nA: " << nonceA << " (stored)" << endl;
        cout << "Is Hash Valid? " << isHashValid << endl;
        cout << "Is Nonce True? " << isNonceTrue << endl;
        cout << "***********************************************************************\n" << endl;
}

void send_rsa_verbose(RSAStorage *rsaStorage, int sequence, char *nonceB)
{
        cout << "Step 4.1" << endl;
    cout << "************ SEND RSA *************************************************" << endl;
    cout << "Generated RSA Key: {(" << rsaStorage->getMyPublicKey()->d
         << ", " << rsaStorage->getMyPublicKey()->n << "), ("
         << rsaStorage->getMyPrivateKey()->d << ", "
         << rsaStorage->getMyPrivateKey()->n << ")}" << endl;
    cout << "My FDR: " << rsaStorage->getMyFDR()->toString() << endl;
    cout << "Sequence: " << sequence << endl << endl;
    cout << "nB: " << nonceB << " (gen)" << endl;
    cout << "***********************************************************************\n" << endl;
}

void recv_rsa_ack_verbose(char *nonceA, bool isHashValid, bool isAnswerCorrect, bool isNonceTrue)
{
        cout << "Step 5.2" << endl;
        cout << "************ RECV ACK RSA *********************************************" << endl;
        cout << "nA: " << nonceA << " (stored)" << endl;
        cout << "Is Hash Valid? " << isHashValid << endl;
        cout << "Is Nonce True? " << isNonceTrue << endl;
        cout << "Is Answer Correct? " << isAnswerCorrect << endl;
        cout << "***********************************************************************\n" << endl;
}

void time_limit_burst_verbose()
{
        cout << "*** TIME LIMIT BURST ***" << endl;
}

void send_dh_verbose(DiffieHellmanPackage *dhPackage, int sequence, double tp)
{
        cout << "Step 6.1" << endl;
        cout << "************ SEND DH **************************************************" << endl;
        cout << "Result: " << dhPackage->getResult() << endl;
        cout << "g: " << dhPackage->getBase() << endl;
        cout << "p: " << dhPackage->getModulus() << endl;
        cout << "Sequence: " << sequence << endl;
        cout << "nB: " << dhPackage->getNonceB() << " (gen)" << endl;
        cout << "IV: " << dhPackage->getIV() << endl;
        cout << "tp: " << tp << " ms" << endl;
        cout << "***********************************************************************\n" << endl;
}

void recv_dh_verbose(DiffieHellmanPackage *dhPackage, int sessionKey, bool isHashValid, bool isNonceTrue)
{
    cout << "Step 7.2" << endl;
    cout << "************ RECV DH **************************************************" << endl;
    cout << "Session Key: " << sessionKey << endl;
    cout << "nA: " << dhPackage->getNonceB() << " (stored)" << endl;
    cout << "Is Hash Valid? " << isHashValid << endl;
    cout << "Is Nonce True? " << isNonceTrue << endl;
    cout << "***********************************************************************\n" << endl;
}

void send_dh_ack_verbose(DH_ACK *ack)
{
        cout << "Step 8.1" << endl;
        cout << "************ SEND DH ACK **********************************************" << endl;
        cout << "ACK" << endl;
        cout << "nA: " << ack->nonce << endl << endl;
        cout << "***********************************************************************\n" << endl;
}


void rft_verbose()
{
        cout << "***********************************************************************"   << endl;
        cout << "Request for termination received." << endl;
        cout << "DONE ACK sent." << endl;
        cout << "End of connection." << endl;
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
        cout << "***********************************************************************" << endl;
        cout << "Send DONE to Client." << endl;
        cout << "***********************************************************************\n" << endl;    
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