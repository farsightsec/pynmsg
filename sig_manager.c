#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <Python.h>

extern int pynmsg_raise_signal(int sig);

static void pynmsg_sighandler(int sig)
{
    PyErr_SetInterrupt();
    pynmsg_raise_signal(sig);
}

__attribute__((unused))
static void setup_sighandler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = pynmsg_sighandler;
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL))
        perror("sigaction");
    if (sigaction(SIGINT, &sa, NULL))
        perror("sigaction");
    if (sigaction(SIGALRM, &sa, NULL))
        perror("sigaction");
}


