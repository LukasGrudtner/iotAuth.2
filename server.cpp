#include <iostream>
#include "Auth/AuthServer.h"

#include "Socket/UDPSocket.h"

using namespace std;

AuthServer auth;

int main(int argc, char *argv[])
{
    char data[] = "hello";

    auth.wait_connection();
    
    if (auth.isConnected())
    {
        cout << "Received: " << auth.listen() << endl;
        cout << "Sent: " << data << endl;
        cout << "Publish: " << auth.publish(data) << endl;

        try{
            auth.listen();
        }
        catch (status e)
        {
            cerr << "Erro: " << e << endl;
        }
        
        auth.disconnect();
    }

    // UDPSocket udp;
    // udp.connect();
    
    // structSyn recv;
    // udp.recv(&recv, sizeof(recv));

    // char *str = new char[100];
    // ByteArrayToHexString(recv.nonce, 33, str, 65);

    // cout << "Recv: " << str << endl;

}