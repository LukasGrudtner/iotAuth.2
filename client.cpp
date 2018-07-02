#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <array>
#include <iostream>
#include "iotAuth.h"
#include "utils.h"
#include "settings.h"
#include "Arduino.h"

using namespace std;

Arduino arduino;

int main(int argc, char *argv[])
{
    double start = currentTime();

    arduino.connect(argv[1]);

    char data[] = "teste";
    arduino.publish(data);

    char data1[] = "teste2";
    arduino.publish(data1);

    double end = currentTime();
    cout << "Elapsed Time: " << elapsedTime(start, end) << " ms." << endl;
}
