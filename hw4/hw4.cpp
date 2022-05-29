#include <iostream>
#include <fstream>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <vector>
#include <sstream>
#include <capstone/capstone.h>

#include "hw4.h"
#include "helper.h"


using namespace std;
vector<string> script_lines;
vector<string> split;
vector<point> breakpoints;
string program;
state status;

void parse(const string &command, vector<string> &split) {
    split.clear();
    stringstream ss;
    ss << command;
    string s;
    while (ss >> s) {
        split.push_back(s);
    }
}

int main(int argc, char **argv) {
    char c;
    char *svalue = NULL;
    opterr = 0;
    status = NOT_LOADED;
    string command;
	pid_t child;
    while ((c = getopt(argc, argv, "s:")) != -1) {
        switch (c) {
            case 's':
                svalue = optarg;
                break;
            default:
		        fprintf(stderr, "usage: %s [-s script] [program]\n", argv[0]);
                exit(1);
        }
    }
    if (svalue) {
        printf("** script path: %s\n", svalue);
        fstream script(svalue, ios::in);
        script_lines.clear();
        if (script.is_open()) {
            while (getline(script, command)) {
                script_lines.push_back(command);
            }
            script.close();
        }
        // ...
    }
    // last arg is the program
	int wait_status;
    if (argv[optind]) {
        program = argv[optind];
        fstream file(program, ios::binary | ios::in);
        unsigned long elf;
        for (int i = 0; i < 4; i++)
            file.read((char *) &elf, sizeof(unsigned long));
        file.close();
        printf("** program '%s' loaded. entry point 0x%lx\n", argv[optind], elf);
        status = LOADED;
        //...
    }
    int has_script = !script_lines.empty();
    while (1) {
        if (has_script) {
            if (script_lines.empty())
                break;
            command = script_lines[0];
            script_lines.erase(script_lines.begin());
        }
        else {
            printf("sdb> ");
            getline(cin, command);
        }
        parse(command, split);
        if (split.empty())
            continue;
        else if (split[0] == "break" || split[0] == "b") {
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            if (split.size() != 2) {
                printf("** no address is given\n");
                continue;
            }

            /* get original text: 48 39 d0 */
            unsigned long addr = stoul(split[1], nullptr, 16);
            unsigned long code;
		    code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
            point bp = {addr, (code & 0xff)};
            int has_bp = 0;
            for (int i = 0; i < (int)breakpoints.size(); i++) {
                if (breakpoints[i].addr == addr) {
                    printf("** the breakpoint already exists (breakpoint %d)\n", i);
                    has_bp = 1;
                    break;
                }
            }
            if (has_bp) continue;
            breakpoints.push_back(bp);
            printf("** original inst: %x\n", bp.inst);
            /* set break point */
            if(ptrace(PTRACE_POKETEXT, child, addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
                errquit("ptrace(POKETEXT)");

        }
        else if (split[0] == "cont" || split[0] == "c") {
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            recover_breakpoint(child, breakpoints);
			if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
			if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
            if (!WIFSTOPPED(wait_status)) {
                printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(wait_status));
                status = LOADED;
                continue;
            }
            struct user_regs_struct regs;
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
            regs.rip = regs.rip-1;
            printf("** breakpoint @ 0x%llx\n", regs.rip);
            if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
        }
        else if (split[0] == "delete") {
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            if (split.size() < 2 || !isNumber(split[1])) {
                printf("** no index is given\n");
                continue;
            }
            int index = stoi(split[1]);
            if (index >= (int)breakpoints.size() || index < 0) {
                printf("** index not exist!\n");
                continue;
            }
            point bp = breakpoints[index];
            breakpoints.erase(breakpoints.begin() + index);
            printf("** breakpoint %d deleted.\n", index);
            unsigned long code;
            code = ptrace(PTRACE_PEEKTEXT, child, bp.addr, 0);
            code = (code & ~0xff) | bp.inst;
            if(ptrace(PTRACE_POKETEXT, child, bp.addr, code) != 0) errquit("ptrace(POKETEXT)");
        }
        else if (split[0] == "disasm" || split[0] == "d") {
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            if (split.size() < 2) {
                printf("** no address is given\n");
                continue;
            }
            unsigned long addr = stoul(split[1], nullptr, 16);
            _disasm(addr, child, breakpoints);
            //...
        }
        else if (split[0] == "dump") { // fin
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            if (split.size() < 2) {
                printf("** no address is given\n");
                continue;
            }
            unsigned long target = stoul(split[1], nullptr, 16);
		    _dump(target, child);
        }
        else if (split[0] == "exit" || split[0] == "q") { // fin
            exit(0);
        }
        else if (split[0] == "get" || split[0] == "g") { //fin
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            _get(child, split[1]);
        }
        else if (split[0] == "getregs") {
            if (status != RUNNING) {
                printf("** state must be running\n");
                continue;
            }
            _getregs(child);
        }
        else if (split[0] == "help") { // fin
            cout << help_message;
        }
        else if (split[0] == "list" || split[0] == "l") {
            for (int i = 0; i < (int)breakpoints.size(); i++) {
                printf("\t%d: 0x%lx\n", i, breakpoints[i].addr);
            }
        }
        else if (split[0] == "load") { // fin
            if (status != NOT_LOADED) {
                printf("** state must be NOT LOADED\n");
                continue;
            }
            if (split.size() < 2) {
                printf("** no program path is given\n");
                continue;
            }
            program = split[1];
            fstream file(program, ios::binary | ios::in);
            unsigned long elf;
            for (int i = 0; i < 4; i++)
                file.read((char *) &elf, sizeof(unsigned long));
            file.close();
            printf("** program '%s' loaded. entry point 0x%lx\n", program.c_str(), elf);
            status = LOADED;
        }
        else if (split[0] == "run") {
            if (status == RUNNING) {
                printf("** the program is running.\n");
            }
            else if (status == LOADED) {
                if((child = fork()) < 0) errquit("fork");
                if (child == 0) {
                    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
                    execlp(program.c_str(), program.c_str(), NULL);
                    errquit("execlp");
                } else {
                    printf("** pid %d\n", child);
                    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
                    assert(WIFSTOPPED(wait_status));
                    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
                }
                load_breakpoints(child, breakpoints);
                status = RUNNING;
            }
            else {
                printf("** must in RUNNING or LOADED state.\n");
                continue;
            }
            recover_breakpoint(child, breakpoints);
			if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
			if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
            if (!WIFSTOPPED(wait_status)) {
                printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(wait_status));
                status = LOADED;
                continue;
            }
            struct user_regs_struct regs;
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
            regs.rip = regs.rip-1;
            printf("** breakpoint @ 0x%llx\n", regs.rip);
            if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
        }
        else if (split[0] == "si") { // fin
            if (status != RUNNING) {
                printf("** state must be RUNNING.\n");
                continue;
            }
            recover_breakpoint(child, breakpoints);
			if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("ptrace(SINGLESTEP)");
			if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
            if (!WIFSTOPPED(wait_status)) {
                printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(wait_status));
                status = LOADED;
                continue;
            }
            struct user_regs_struct regs;
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
            unsigned long code;
            unsigned long addr = regs.rip;
            code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
            if ((code & 0xff) == 0xcc) {
                printf("** breakpoint @ 0x%lx\n", addr);
                regs.rip = regs.rip+1;
                if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
            }
            //..
        }
        else if (split[0] == "set" || split[0] == "s") {
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            if (split.size() != 3) {
                printf("** set [reg] [value]\n");
                continue;
            }
            unsigned long addr = stoul(split[2], nullptr, 16);
            _set(child, split[1], addr);

        }
        else if (split[0] == "start") { // fin
            if (status != LOADED) {
                printf("** state must be LOADED\n");
                continue;
            }
            if((child = fork()) < 0) errquit("fork");
            if (child == 0) {
                if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
                execlp(program.c_str(), program.c_str(), NULL);
                errquit("execlp");
            } else {
                printf("** pid %d\n", child);
                if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
                assert(WIFSTOPPED(wait_status));
                ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
            }
            load_breakpoints(child, breakpoints);
            status = RUNNING;
        }
        else if (split[0] == "vmmap" || split[0] == "m") { // need parse
            if (status != RUNNING) {
                printf("** state must be RUNNING\n");
                continue;
            }
            string map_path = "/proc/" + to_string(child) + "/maps";
            string map_line;
            fstream vmmap(map_path, ios::in);
            if (vmmap.is_open()) {
                unsigned long start_addr, end_addr;
                string perms;
                unsigned offset;
                string pathname;
                char c;
                string no_use;
                while (getline(vmmap, map_line)) {
                    stringstream ss(map_line);
                    ss >> hex >> start_addr >> c >> end_addr;
                    ss >> perms >> offset >> no_use >> no_use >> pathname;
                    printf("%016lx-%016lx %s %-8x %s\n",
                        start_addr,
                        end_addr,
                        perms.substr(0, 3).c_str(),
                        offset,
                        pathname.c_str());
                }
            }
            // char cmd[128];
            // sprintf(cmd, "cat /proc/%d/maps", child);
            // system(cmd);
        }
        else {
            printf("** Wrong command!!");
            continue;
        }

        if (status == RUNNING) {
            load_breakpoints(child, breakpoints);
            assert(WIFSTOPPED(wait_status));
        }
      
    }
    return 0;
}
