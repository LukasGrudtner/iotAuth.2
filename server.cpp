#include <iostream>
#include "Auth/AuthServer.h"

using namespace std;

AuthServer auth;

int main(int argc, char *argv[])
{
    // char data[] = "hello";

    auth.wait_connection();
    double end = currentTime();

    if (auth.isConnected())
    {
        cout << "Elapsed time: " << elapsedTime(auth.start, end) << "ms." << endl;
    }
    
    // if (auth.isConnected())
    // {
    //     cout << "Received: " << auth.listen() << endl;
    //     cout << "Sent: " << data << endl;
    //     cout << "Publish: " << auth.publish(data) << endl;

    //     try{
    //         auth.listen();
    //     }
    //     catch (status e)
    //     {
    //         cerr << "Erro: " << e << endl;
    //     }
        
    //     auth.disconnect();
    // }
}