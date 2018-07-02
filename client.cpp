#include <iostream>
#include "Auth/AuthClient.h"

using namespace std;

AuthClient auth;

int main(int argc, char *argv[])
{
    double start = currentTime();

    auth.connect(argv[1]);

    char data[] = "teste";
    auth.publish(data);

    char data1[] = "teste2";
    auth.publish(data1);

    auth.disconnect();

    double end = currentTime();
    cout << "Elapsed Time: " << elapsedTime(start, end) << " ms." << endl;
}
