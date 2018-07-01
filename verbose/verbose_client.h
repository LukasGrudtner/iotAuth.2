#ifndef VERBOSE_CLIENT_H
#define VERBOSE_CLIENT_H

#include <iostream>
#include <string>
#include "../RSA/RSAStorage.h"
#include "../RSA/RSAKeyExchange.h"
#include "../Diffie-Hellman/DHStorage.h"
#include "../Diffie-Hellman/DiffieHellmanPackage.h"

using namespace std;

void send_syn_verbose(char *nonce);
void recv_ack_verbose(char *nonceB, int sequence, char *serverIP, char *clientIP, bool isNonceTrue);
void send_rsa_verbose(RSAStorage *rsaStorage, int sequence, char *nonceA);
void recv_rsa_verbose(RSAStorage *rsaStorage, char *nonceB, bool isHashValid, bool isNonceTrue, bool isAnswerCorrect);
void send_rsa_ack_verbose(int sequence, char *nonceA);
void recv_dh_verbose(DiffieHellmanPackage *dhPackage, bool isHashValid, bool isNonceTrue);
void send_dh_verbose(DiffieHellmanPackage *dhPackage, int sessionKey, int sequence, double tp);
void send_dh_ack_verbose(DH_ACK *ack, bool isNonceTrue);

void time_limit_burst_verbose();

void wdc_verbose();
void rft_verbose();
void done_verbose();

void sdh_verbose(DiffieHellmanPackage *dhPackage);
void rdh_verbose1(DHStorage *dhStorage, DiffieHellmanPackage *dhPackage, string *hash);
void rdh_verbose2();
void rdh_verbose3();
void rdh_verbose4();
void dt_verbose1();
void dt_verbose2(string *sent);

void response_timeout_verbose();

void reply_verbose(Reply reply);

#endif