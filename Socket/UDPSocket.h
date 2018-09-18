#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <strings.h>

#include "../settings.h"

typedef struct Socket
{
    int socket;
    struct sockaddr *remote;
    socklen_t size;
} t_socket;

class UDPSocket
{

  public:
    /* For servers */
    int connect();
    /* For clients */
    int connect(char *address, int port);
    void max_response_time(int seconds, int milliseconds);
    char *server_address();
    char *client_address();
    int send(const void *buffer, size_t size);
    int recv(void *buffer, size_t size);
    int finish();

  private:
    Socket soc;

    struct sockaddr_in servidor, cliente;

    int meuSocket;
    socklen_t tam_cliente;
    struct hostent *server;
    char host_name[256];
    char client_name[256];
};

#endif