#ifdef USEMINI
#include "libmini.h"
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <signal.h>
#endif

#define echo(msg) write(0, (msg), sizeof(msg))
void print_num(int num);

sigset_t mask, oldmask;
static jmp_buf buf;

void B(void) {
    echo("B():\n");

    sigprocmask(SIG_SETMASK, &oldmask, NULL);
    echo("signal mask reseted.\n");

#ifdef USEMINI
    longjmp(buf, 6);
#else
    siglongjmp(buf, 6);
#endif
}

void A(void) {
    echo("A():\n");
    int x = 10;

    echo("x before jump = "); print_num(x); echo("\n");

    sigemptyset(&mask);
    print_num(sigaddset(&mask, SIGINT));
    sigaddset(&mask, SIGABRT);
    sigprocmask(SIG_SETMASK, &mask, &oldmask);

    int jmp_return;

#ifdef USEMINI
    if ((jmp_return = setjmp(buf)) == 0) {
#else
    if ((jmp_return = sigsetjmp(buf, 1)) == 0) {
#endif
        echo("jmp_return = "); print_num(jmp_return); echo("\n");
        x = 20;
        B();
    }

    echo("jumped\n");
    echo("jmp_return = "); print_num(jmp_return); echo("\n");
    echo("x after jump = "); print_num(x); echo("\n");

    sigset_t pending;
    if (sigpending(&pending) < 0) {
        perror("sigpending");
        exit(1);
    }
    if (sigismember(&pending, SIGINT) == 1)
        echo("SIGINT is pending.\n");
}

void sigint_handler(int sig) {
    echo("handled\n");
}

int main(void) {
    signal(SIGINT, sigint_handler);
    A();
    echo("finished\n");
    return 0;
}

void print_num(int num) {
    if (num == 0) {
        write(0, "0", 1);
        return;
    }

    if (num == -1) {
        write(0, "-1", 2);
        return;
    }
    char num_s[11];
    num_s[10] = '\0';
    int curr = 9;
    while (num) {
        num_s[curr--] = '0' + (num % 10);
        num /= 10;
    }
    char* msg = num_s + curr + 1;
    write(0, msg, strlen(msg));
}
