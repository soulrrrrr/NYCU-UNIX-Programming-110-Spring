#ifndef _HELPER_H
#define _HELPER_H

#include <iostream>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string>
#include <vector>
#include <capstone/capstone.h>
#include <string.h>
#include <elf.h>
#include <fstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "hw4.h"
using namespace std;

#define PEEKSIZE 8

void _dump(unsigned long target, pid_t child);
void _disasm(unsigned long addr, pid_t child, vector<point> &breakpoints);
void _get(pid_t child, string reg);
void _getregs(pid_t child);
void add_breakpoint(pid_t child, unsigned long addr, vector<point> &breakpoints);
void load_breakpoints(pid_t child, vector<point> &breakpoints);
void recover_breakpoint(pid_t child, vector<point> &breakpoints);
void _set(pid_t child, string reg, unsigned long value);
bool isNumber(const string& s);
void errquit(const char *msg);

extern string help_message;

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif // __LP64__

#endif