#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H

#include <Ethernet.h>
#include <EthernetUdp.h>

EthernetUDP Udp;

// Enter a MAC address and IP address for your controller below.
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
// The IP address will be dependent on your local network:
IPAddress ip(150, 162, 63, 205);
IPAddress pc(150, 162, 63, 204);

int localPort = 8080;      // local port to listen on

class UDPSocket
{
    int connect(char *address, int port);
    void max_response_time(int seconds, int milliseconds);
    char *server_address();
    char *client_address();
    int send(char *data);
    int recv(void *buffer, size_t size);
    int finish();
};

#endif