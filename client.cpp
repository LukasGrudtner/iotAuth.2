#include <iostream>
#include "Auth/AuthClient.h"

using namespace std;

AuthClient auth;

int main(int argc, char *argv[])
{
    double start = currentTime();

    auth.connect(argv[1]);

    char data[] = "oi";

    if (auth.isConnected())
    {
        cout << "Sent: " << data << endl;
        auth.publish(data);
        cout << "Received: " << auth.listen() << endl;
        // auth.disconnect();
    }

    double end = currentTime();
    cout << "Elapsed Time: " << elapsedTime(start, end) << " ms." << endl;
}
