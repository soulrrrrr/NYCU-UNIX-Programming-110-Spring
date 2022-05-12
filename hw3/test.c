#include <stdio.h>

void bar() {
    int a = 0;
}

void foo() {
    bar();
}

int main() {
    foo();
}