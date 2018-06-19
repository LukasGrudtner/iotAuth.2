#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <array>
#include <iostream>
#include "iotAuth.h"
#include "utils.h"
#include "settings.h"
#include "Arduino.h"
#include <sys/time.h>

using namespace std;

Arduino arduino;

int main(int argc, char *argv[]){

    struct sockaddr_in servidor, cliente;
    
    int meuSocket;
    socklen_t tam_cliente;
    char envia[556];
    char recebe[10000];
    struct hostent *server;

    if (argv[1] == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bcopy((char *)server->h_addr,
         (char *)&servidor.sin_addr.s_addr,
         server->h_length);

    meuSocket=socket(PF_INET,SOCK_DGRAM,0);
    servidor.sin_family=AF_INET; // familia de endereços
    servidor.sin_port=htons(DEFAULT_PORT); // porta
    // para usar um ip qualquer use inet_addr("10.10.10.10"); ao invés de htonl(INADDR_ANY)
    // servidor.sin_addr.s_addr=htonl(INADDR_ANY);
    // servidor.sin_addr.s_addr=inet_addr("150.162.237.172");

    memset(envia, 0, sizeof(envia));
    memset(recebe, 0, sizeof(recebe));

    tam_cliente=sizeof(struct sockaddr_in);

    // struct in_addr ipAddrClient = cliente.sin_addr;
    // struct in_addr ipAddrServer = servidor.sin_addr;

    while(1){

    //     char ipServer[INET_ADDRSTRLEN];
    //     char ipClient[INET_ADDRSTRLEN];
    //     inet_ntop( AF_INET, &ipAddrClient, ipClient, INET_ADDRSTRLEN );
    //     inet_ntop( AF_INET, &ipAddrServer, ipServer, INET_ADDRSTRLEN );

    //    cout << "IP CLIENT: " << ipClient << endl;
    //    cout << "IP SERVER: " << ipServer << endl;

        arduino.stateMachine(meuSocket, (struct sockaddr*)&servidor, tam_cliente);

    }
    close(meuSocket);
}
