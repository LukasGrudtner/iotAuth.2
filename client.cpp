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

using namespace std;

Arduino arduino;

struct sockaddr_in servidor, cliente;

int meuSocket;
socklen_t tam_cliente;
char envia[556];
char recebe[10000];
struct hostent *server;
char host_name[256];
char client_name[256];

int connect(char *address)
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
    servidor.sin_family = AF_INET;           // familia de endereços
    servidor.sin_port = htons(DEFAULT_PORT); // porta

    /* Set maximum wait time for response */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_MIC;
    setsockopt(meuSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    /* Get IP Address Server */
    gethostname(host_name, sizeof(host_name));
    server = gethostbyname(host_name);
    arduino.serverIP = inet_ntoa(*(struct in_addr *)*server->h_addr_list);

    /* Get IP Address Client */
    struct hostent *client;
    gethostname(client_name, sizeof(client_name));
    client = gethostbyname(client_name);
    arduino.clientIP = inet_ntoa(*(struct in_addr *)*client->h_addr_list);

    Socket soc = {meuSocket, (struct sockaddr *)&servidor, sizeof(struct sockaddr_in)};

    try
    {
        arduino.send_syn(&soc);
    }
    catch (Reply e)
    {
        cerr << "Erro: " << e << endl;
        return e;
    }

    return OK;
}

int main(int argc, char *argv[])
{

    memset(envia, 0, sizeof(envia));
    memset(recebe, 0, sizeof(recebe));

    double start = currentTime();

    connect(argv[1]);

    double end = currentTime();
    cout << "Elapsed Time: " << elapsedTime(start, end) << " ms." << endl;
}
