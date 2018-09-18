#include "UDPSocket.h"

int UDPSocket::connect(char *address, int port)
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
    servidor.sin_family = AF_INET;   // familia de endereços
    servidor.sin_port = htons(port); // porta

    soc = {meuSocket, (struct sockaddr *)&servidor, sizeof(struct sockaddr_in)};
    return OK;
}

void UDPSocket::max_response_time(int seconds, int microseconds)
{
    /* Set maximum wait time for response */
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = microseconds;
    setsockopt(meuSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
}

char *UDPSocket::server_address()
{
    /* Get IP Address Server */
    gethostname(host_name, sizeof(host_name));
    server = gethostbyname(host_name);
    return inet_ntoa(*(struct in_addr *)*server->h_addr_list);
}

char *UDPSocket::client_address()
{
    /* Get IP Address Client */
    struct hostent *client;
    gethostname(client_name, sizeof(client_name));
    client = gethostbyname(client_name);
    return inet_ntoa(*(struct in_addr *)*client->h_addr_list);
}

int UDPSocket::send(const void *buffer, size_t size)
{
    return sendto(soc.socket, buffer, size, 0, soc.remote, soc.size);
}

int UDPSocket::recv(void *buffer, size_t size)
{
    return recvfrom(soc.socket, buffer, size, 0, soc.remote, &soc.size);
}

int UDPSocket::finish()
{
    return close(soc.socket);
}