#include <iostream>
#include "Auth/AuthServer.h"

using namespace std;

AuthServer auth;

int main(int argc, char *argv[])
{
    char data[] = "hello";

    auth.wait_connection();
    
    if (auth.isConnected())
    {
        sleep(5);
        cout << "Received: " << auth.listen() << endl;
        cout << "Sent: " << data << endl;
        auth.publish(data);
        auth.listen();
    }
}