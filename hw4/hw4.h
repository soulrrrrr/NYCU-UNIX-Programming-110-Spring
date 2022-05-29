#ifndef _HW4_H
#define _HW4_H

#include <string>
using namespace std;
enum state {
    NOT_LOADED,
    LOADED,
    RUNNING
};

struct point {
    unsigned long addr;
    unsigned char inst;
};

extern string program;

#endif