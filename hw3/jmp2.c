#include "libmini.h"

static jmp_buf jmpbuf;
static int canjump;
static void sig_alrm(int signo) {
    char m[] = "sigalrm is pending.\n";
    write(1, m, strlen(m));
}
static void sig_usr1(int signo) {
    if (canjump == 0) return; /* unexpected signal, ignore */
    char m[] = "start sig_usr1.\n";
    write(1, m, strlen(m));
    alarm(3);                 /* SIGALRM in 3 seconds */
    sleep(5);
    char n[] = "end sig_usr1.\n";
    write(1, n, strlen(n));
    canjump = 0;
    longjmp(jmpbuf, 1); /* jump back to main, don't return */
}
int main(void) {
    signal(SIGUSR1, sig_usr1);
    signal(SIGALRM, sig_alrm);
    char m[] = "main.\n";
    write(1, m, strlen(m));
    if (setjmp(jmpbuf)) {
        char m[] = "end main.\n";
        write(1, m, strlen(m));
        exit(0);
    }
    canjump = 1; /* now sigsetjmp() is OK */
    for (;;)
        pause();
}