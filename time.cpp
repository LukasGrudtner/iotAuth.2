#include "time.h"

double currentTime()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)(tv.tv_sec) + (double)(tv.tv_usec)/ 1000000.00;
}

double elapsedTime(double t1, double t2)
{
    return (double)(t2-t1)*1000;
}