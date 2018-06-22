#include "verbose_server.h"

void recv_syn_verbose(char *nonceA)
{
        cout << "Step 1.2" << endl;
    cout << "*********** RECV SYN *****************************************************" << endl;
    cout << "nA: " << nonceA << " (stored)" << endl;
    cout << "**************************************************************************\n"   << endl;
}

void send_ack_verbose(char *nonceB, int sequence, char *serverIP, char *clientIP)
{
        cout << "Step 2.1" << endl;
        cout << "*********** SEND ACK *****************************************************" << endl;
        cout << "nB: " << nonceB << " (generated)" << endl;
        cout << "Sequence: " << sequence << endl << endl;
        cout << "Server IP: " << serverIP << endl;
        cout << "Client IP: " << clientIP << endl;
        cout << "**************************************************************************\n"   << endl;
}

void recv_rsa_verbose(RSAStorage *rsaStorage, char *nonceA, bool isHashValid, bool isNonceTrue)
{
        cout << "Step 3.2" << endl;
        cout << "************ RECV RSA ****************************************************" << endl;
        cout << "Client Public Key: {(" << rsaStorage->getPartnerPublicKey()->d
                << ", " << rsaStorage->getPartnerPublicKey()->n << "), ("
                << rsaStorage->getPartnerPublicKey()->d << ", "
                << rsaStorage->getPartnerPublicKey()->n << ")}" << endl;
        cout << "nA: " << nonceA << " (stored)" << endl;
        cout << "Is Hash Valid? " << isHashValid << endl;
        cout << "Is Nonce True? " << isNonceTrue << endl;
        cout << "**************************************************************************\n" << endl;
}

void send_rsa_verbose(RSAStorage *rsaStorage, int sequence, char *nonceB)
{
        cout << "Step 4.1" << endl;
    cout << "************ SEND RSA ****************************************************" << endl;
    cout << "Generated RSA Key: {(" << rsaStorage->getMyPublicKey()->d
         << ", " << rsaStorage->getMyPublicKey()->n << "), ("
         << rsaStorage->getMyPrivateKey()->d << ", "
         << rsaStorage->getMyPrivateKey()->n << ")}" << endl;
    cout << "My FDR: " << rsaStorage->getMyFDR()->toString() << endl;
    cout << "Sequence: " << sequence << endl << endl;
    cout << "nB: " << nonceB << " (generated)" << endl;
    cout << "**************************************************************************\n" << endl;
}

void recv_rsa_ack_verbose(char *nonceA, bool isHashValid, bool isAnswerCorrect, bool isNonceTrue)
{
        cout << "Step 5.2" << endl;
        cout << "************ RECV ACK RSA ************************************************" << endl;
        cout << "nA: " << nonceA << " (stored)" << endl;
        cout << "Is Hash Valid? " << isHashValid << endl;
        cout << "Is Nonce True? " << isNonceTrue << endl;
        cout << "Is Answer Correct? " << isAnswerCorrect << endl;
        cout << "**************************************************************************\n" << endl;
}

void time_limit_burst_verbose()
{
        cout << "*** TIME LIMIT BURST ***" << endl;
}

void send_dh_verbose(DiffieHellmanPackage *dhPackage, int sequence, double tp)
{
        cout << "Step 6.1" << endl;
        cout << "************ SEND DH *****************************************************" << endl;
        cout << "Result: " << dhPackage->getResult() << endl;
        cout << "g: " << dhPackage->getBase() << endl;
        cout << "p: " << dhPackage->getModulus() << endl;
        cout << "Sequence: " << sequence << endl;
        cout << "nB: " << dhPackage->getNonceB() << " (generated)" << endl;
        cout << "tp: " << tp << " ms" << endl;
        cout << "**************************************************************************\n" << endl;
}

void recv_dh_verbose(DiffieHellmanPackage *dhPackage, int sessionKey, bool isHashValid, bool isNonceTrue)
{
    cout << "Step 7.2" << endl;
    cout << "************ RECV DH *****************************************************" << endl;
    cout << "Session Key: " << sessionKey << endl;
    cout << "nA: " << dhPackage->getNonceB() << " (stored)" << endl;
    cout << "Is Hash Valid? " << isHashValid << endl;
    cout << "Is Nonce True? " << isNonceTrue << endl;
    cout << "**************************************************************************\n" << endl;
}


void rft_verbose()
{
        cout << "\n*******DONE CLIENT AND SERVER******"   << endl;
        cout << "Done Client and Server Successful!"      << endl;
        cout << "***********************************\n"   << endl;
}

void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash)
{
        cout << "\n*******DH | RECEIVE FROM CLIENT******" << endl;
        cout << "THE HASH IS VALID!"            << endl                     << endl;
        cout << "Client Decrypted HASH: "       << *hash                    << endl << endl;
        cout << "Result: "                      << dhPackage->getResult()           << endl;
        cout << "Base: "                        << dhPackage->getBase()             << endl;
        cout << "Modulus: "                     << dhPackage->getModulus()          << endl;
        cout << "Session Key: "                 << dhStorage->getSessionKey()       << endl;
}

void rdh_verbose2()
{
        cout << "Answered FDR ACCEPTED!"                    << endl;
        cout << "**************************************\n"  << endl;
}

void rdh_verbose3()
{
        cout << "Answered FDR REJECTED!"                    << endl;
        cout << "ENDING CONECTION..."                       << endl;
        cout << "**************************************\n"  << endl;
}

void rdh_verbose4()
{
        cout << "THE HASH IS INVALID!" << endl << endl;
}

void sdh_verbose(DiffieHellmanPackage *dhPackage)
{
        cout << "*********DH | SEND TO CLIENT********"                   << endl;
        cout << "Result: "              << dhPackage->getResult()       << endl;
        cout << "Server Package: "      << dhPackage->toString()        << endl;
        cout << "***********************************\n" << endl;
}