#include "verbose_client.h"

void send_syn_verbose(char *nonceA)
{
    cout << "Step 1.1" << endl;
    cout << "*********** SEND SYN ***************************************" << endl;
    cout << "nA: " << nonceA << " (generated)" << endl;
    cout << "**************************************************************************\n"   << endl;
}

void recv_ack_verbose(char *nonceB, int sequence, char *serverIP, char *clientIP, bool isNonceTrue)
{
    cout << "Step 2.2" << endl;
    cout << "*********** RECV ACK *****************************************************" << endl;
    cout << "nB: " << nonceB << " (stored)" << endl;
    cout << "Sequence: " << sequence << endl;
    cout << "Server IP: " << serverIP << endl;
    cout << "Client IP: " << clientIP << endl;
    cout << "Is Nonce True? " << isNonceTrue << endl;
    cout << "**************************************************************************\n"   << endl;
}

void send_rsa_verbose(RSAStorage *rsaStorage, int sequence, char *nonceA)
{
    cout << "Step 3.1" << endl;
    cout << "************ SEND RSA ****************************************************" << endl;
    cout << "Generated RSA Key: {(" << rsaStorage->getMyPublicKey()->d
         << ", " << rsaStorage->getMyPublicKey()->n << "), ("
         << rsaStorage->getMyPrivateKey()->d << ", "
         << rsaStorage->getMyPrivateKey()->n << ")}" << endl;
    cout << "My FDR: " << rsaStorage->getMyFDR()->toString() << endl;
    cout << "Sequence: " << sequence << endl;
    cout << "nA: " << nonceA << " (generated)" << endl;
    cout << "**************************************************************************\n" << endl;
}

void recv_rsa_verbose(RSAStorage *rsaStorage, char *nonceB, bool isHashValid, bool isNonceTrue, bool isAnswerCorrect)
{
    cout << "Step 4.2" << endl;
        cout << "************ RECV RSA ****************************************************" << endl;
        cout << "Ser Public Key: {(" << rsaStorage->getPartnerPublicKey()->d
                << ", " << rsaStorage->getPartnerPublicKey()->n << "), ("
                << rsaStorage->getPartnerPublicKey()->d << ", "
                << rsaStorage->getPartnerPublicKey()->n << ")}" << endl;
        cout << "nB: " << nonceB << " (stored)" << endl;
        cout << "Is Hash Valid? " << isHashValid << endl;
        cout << "Is Nonce True? " << isNonceTrue << endl;
        cout << "Is Answer Correct? " << isAnswerCorrect << endl;
        cout << "**************************************************************************\n" << endl;
}

void send_rsa_ack_verbose(int sequence, char *nonceA)
{
    cout << "Step 5.1" << endl;
    cout << "************ SEND ACK RSA ************************************************" << endl;
    cout << "Sequence: " << sequence << endl;
    cout << "nA: " << nonceA << " (generated)" << endl << endl << endl;
    cout << "**************************************************************************\n" << endl;

}

void time_limit_burst_verbose()
{
        cout << "*** TIME LIMIT BURST ***" << endl;
}

void recv_dh_verbose(DiffieHellmanPackage *dhPackage, bool isHashValid, bool isNonceTrue)
{
    cout << "Step 6.2" << endl;
    cout << "************ RECV DH *****************************************************" << endl;
    cout << "Result: " << dhPackage->getResult() << endl;
    cout << "g: " << dhPackage->getBase() << endl;
    cout << "p: " << dhPackage->getModulus() << endl;
    cout << "nB: " << dhPackage->getNonceB() << " (stored)" << endl;
    cout << "Is Hash Valid? " << isHashValid << endl;
    cout << "Is Nonce True? " << isNonceTrue << endl;
    cout << "**************************************************************************\n" << endl;
}

void send_dh_verbose(DiffieHellmanPackage *dhPackage, int sessionKey, int sequence, double tp)
{
        cout << "Step 7.1" << endl;
        cout << "************ SEND DH *****************************************************" << endl;
        cout << "Session Key: " << sessionKey << endl;
        cout << "Sequence: " << sequence << endl;
        cout << "nA: " << dhPackage->getNonceB() << " (generated)" << endl;
        cout << "tp: " << tp << " ms" << endl;
        cout << "**************************************************************************\n" << endl;
}

void send_dh_ack_verbose(DH_ACK *ack, bool isNonceTrue)
{
        cout << "Step 8.2" << endl;
        cout << "************ RECV DH ACK *************************************************" << endl;
        cout << "ACK" << endl;
        cout << "nA: " << ack->nonce << endl;
        cout << "isNonceTrue? " << isNonceTrue << endl;
        cout << "**************************************************************************\n" << endl;
}

void rft_verbose()
{
    cout << "\n*******DONE CLIENT AND SERVER****"   << endl;
    cout << "Done Client and Server Successful!"      << endl;
    cout << "***********************************\n"   << endl;
}

void sdh_verbose(DiffieHellmanPackage *dhPackage)
{
    cout << "************DH | SEND TO SERVER************" << endl;
    cout << "Result: " << dhPackage->getResult() << endl;
    cout << "Base: " << dhPackage->getBase() << endl;
    cout << "Modulus: " << dhPackage->getModulus() << endl;
    cout << "Sent: " << dhPackage->toString() << endl;
    cout << "**************************************" << endl << endl;
}

void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash)
{
    cout << "\n*******DH | RECEIVE FROM SERVER******" << endl;
    cout << "THE HASH IS VALID!"        << endl                         << endl;
    cout << "Server Decrypted HASH: "   << *hash                        << endl << endl;
    cout << "Session Key: "             << dhStorage->getSessionKey()   << endl;
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