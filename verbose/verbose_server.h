#ifndef VERBOSE_SERVER_H
#define VERBOSE_SERVER_H

#include <iostream>
#include <string>
#include "../RSA/RSAStorage.h"
#include "../Diffie-Hellman/DHStorage.h"
#include "../Diffie-Hellman/DiffieHellmanPackage.h"
#include "../RSA/RSAKeyExchange.h"

using namespace std;

void recv_syn_verbose(char *nonceA);
void send_ack_verbose(char *nonceB, int sequence, char *serverIP, char *clientIP);
void send_rsa_verbose(RSAStorage *rsaStorage, int sequence, char *nonceB);
void recv_rsa_verbose(RSAStorage *rsaStorage, char *nonceA, bool isHashValid, bool isNonceTrue);
void recv_rsa_ack_verbose(char *nonceA, bool isHashValid, bool isAnswerCorrect, bool isNonceTrue);
void send_dh_verbose(DiffieHellmanPackage *dhPackage, int sequence, double tp);
void recv_dh_verbose(DiffieHellmanPackage *dhPackage, int sessionKey, bool isHashValid, bool isNonceTrue);
void send_dh_ack_verbose(DH_ACK *ack);

void time_limit_burst_verbose();

void wdc_verbose();
void rft_verbose();
void done_verbose();

void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash);
void rdh_verbose2();
void rdh_verbose3();
void rdh_verbose4();
void sdh_verbose(DiffieHellmanPackage *dhPackage);

void response_timeout_verbose();

#endif