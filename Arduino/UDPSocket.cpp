#include "UDPSocket.h"

void UDPSocket::connect()
{
    Ethernet.begin(mac, ip);
    Udp.begin(localPort);
}

void UDPSocket::send(char *data)
{
    Udp.beginPacket(pc, localPort);
    Udp.write(sendData);
    Udp.endPacket();
}