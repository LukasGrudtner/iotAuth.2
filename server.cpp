#include <iostream>
#include "Auth/AuthServer.h"

using namespace std;

AuthServer auth;

int main(int argc, char *argv[])
{
    auth.wait();
}