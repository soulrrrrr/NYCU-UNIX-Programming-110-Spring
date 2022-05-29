#include "helper.h"

char ret[128];

char *bytecode(char *buf, int index, int size) {
    memset(ret, 0, sizeof(ret));
    for (int i = index; i < index + size; i++) {
        sprintf(ret, "%s %02x", ret, (uint8_t)buf[i]);
    }
    return ret;
}

unsigned long get_text_end(string program) {
    struct stat st;
    stat(program.c_str(), &st);
    int fd = open(program.c_str(), O_RDONLY);
    char *p = (char *)mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)p;
    ElfW(Shdr) *shdr = (ElfW(Shdr) *)(p + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;
    ElfW(Shdr) *sh_strtab = &shdr[ehdr->e_shstrndx];
    char *sh_strtab_p = p + sh_strtab->sh_offset;
    for (int i = 0; i < shnum; ++i) {
        char *sh_name = sh_strtab_p + shdr[i].sh_name;
        if (strcmp(sh_name, ".text") == 0) {
            return (shdr[i].sh_addr + shdr[i].sh_size);
        }
    }
    return 0;
}

void _disasm(unsigned long addr, pid_t child, vector<point> &breakpoints) {
    csh handle;
	cs_insn *insn;
	size_t count;
    uint8_t buf[129] = {'\0'};
    unsigned long code;
    unsigned long _text_end = get_text_end(program);
    for (unsigned long ptr = addr; ptr < addr + sizeof(buf); ptr += PEEKSIZE) {
        code = ptrace(PTRACE_PEEKTEXT, child, ptr, 0);
		memcpy(&buf[ptr-addr], &code, PEEKSIZE);
    }
    for (auto p : breakpoints) {
        if (p.addr >= addr && p.addr < addr+sizeof(buf)) {
            buf[p.addr-addr] = p.inst;
        }
    }
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return;
	count = cs_disasm(handle, (uint8_t *)buf, sizeof(buf)-1, addr, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
            if (j > 10) break;
            if (insn[j].address >= _text_end) {
                printf("** the address is out of the range of the text segment\n");
                break;
            }
			printf("\t%"PRIx64": %-32s\t%s\t%s\n",
                insn[j].address,
                bytecode((char *)buf, insn[j].address - insn[0].address, insn[j+1].address - insn[j].address),
                insn[j].mnemonic,
				insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("** ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
}

void _dump(unsigned long addr, pid_t child) {
    unsigned long code, code_8;
    for (int i = 0; i < 5; i++) {
        char buf[17];
        printf("\t0x%lx: ", addr);
        code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
        code_8 = ptrace(PTRACE_PEEKTEXT, child, addr+8, 0);
        for (int j = 0; j < 8; j++) {
            printf("%02x ",
                ((unsigned char *) (&code))[j]);
            buf[j] = ((char *) (&code))[j];
        }
        for (int j = 0; j < 8; j++) {
            printf("%02x ",
                ((unsigned char *) (&code_8))[j]);
            buf[j+8] = ((char *) (&code_8))[j];
        }
        buf[16] = '\0';
        printf("|");
        for (int j = 0; j < 16; j++) {
            if (isprint(buf[j])) {
                printf("%c", buf[j]);
            }
            else {
                printf("%c", '.');
            }
        }
        printf("|\n");
        addr += 16;
    }
}

void _get(pid_t child, string reg) {
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) < 0) return;
    if (reg == "rax")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rax, regs.rax);
    else if (reg == "rbx")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rbx, regs.rbx);
    else if (reg == "rcx")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rcx, regs.rcx);
    else if (reg == "rdx")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rdx, regs.rdx);
    else if (reg == "r8")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r8, regs.r8);
    else if (reg == "r9")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r9, regs.r9);
    else if (reg == "r10")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r10, regs.r10);
    else if (reg == "r11")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r11, regs.r11);
    else if (reg == "r12")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r12, regs.r12);
    else if (reg == "r13")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r13, regs.r13);
    else if (reg == "r14")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r14, regs.r14);
    else if (reg == "r15")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.r15, regs.r15);
    else if (reg == "rdi")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rdi, regs.rdi);
    else if (reg == "rsi")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rsi, regs.rsi);
    else if (reg == "rbp")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rbp, regs.rbp);
    else if (reg == "rsp")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rsp, regs.rsp);
    else if (reg == "rip")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.rip, regs.rip);
    else if (reg == "flags")
        printf("%s = %llu (0x%llx)\n", reg.c_str(), regs.eflags, regs.eflags);
    else
        printf("** not valid register.\n");
}

void _getregs(pid_t child) {
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) < 0) return;
    printf("RAX %-16llx RBX %-16llx RCX %-16llx RDX %-16llx\n",
        regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("R8  %-16llx R9  %-16llx R10 %-16llx R11 %-16llx\n",
        regs.r8, regs.r9, regs.r10, regs.r11);
    printf("R12 %-16llx R13 %-16llx R14 %-16llx R15 %-16llx\n",
        regs.r12, regs.r13, regs.r14, regs.r15);
    printf("RDI %-16llx RSI %-16llx RBP %-16llx RSP %-16llx\n",
        regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    printf("RIP %-16llx FLAGS %016llx\n",
        regs.rip, regs.eflags);
}

void _set(pid_t child, string reg, unsigned long value) {
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
    if (reg == "rax")
        regs.rax = value;
    else if (reg == "rbx")
        regs.rbx = value;
    else if (reg == "rcx")
        regs.rcx = value;
    else if (reg == "rdx")
        regs.rdx = value;
    else if (reg == "r8")
        regs.r8 = value;
    else if (reg == "r9")
        regs.r9 = value;
    else if (reg == "r10")
        regs.r10 = value;
    else if (reg == "r11")
        regs.r11 = value;
    else if (reg == "r12")
        regs.r12 = value;
    else if (reg == "r13")
        regs.r13 = value;
    else if (reg == "r14")
        regs.r14 = value;
    else if (reg == "r15")
        regs.r15 = value;
    else if (reg == "rdi")
        regs.rdi = value;
    else if (reg == "rsi")
        regs.rsi = value;
    else if (reg == "rbp")
        regs.rbp = value;
    else if (reg == "rsp")
        regs.rsp = value;
    else if (reg == "rip")
        regs.rip = value;
    else if (reg == "flags")
        regs.eflags = value;
    else {
        printf("** not valid register.\n");
        return;
    }
    if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");

}

void recover_breakpoint(pid_t child, vector<point> &breakpoints) {
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
    unsigned long addr = regs.rip;
    unsigned long code;
    code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
    int has_bp = 0;
    /* restore break point */
    for (auto &p : breakpoints) {
        if (p.addr == addr) {
            code = (code & ~0xff) | p.inst;
            has_bp = 1;
            break;
        }
    }
    if (has_bp == 0) return;
    if(ptrace(PTRACE_POKETEXT, child, addr, code) != 0) errquit("ptrace(POKETEXT)");
    // /* set PC back */
    // regs.rip = regs.rip-1;
    // if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
}

void load_breakpoints(pid_t child, vector<point> &breakpoints) {
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
    unsigned long code;
    /* restore break point */
    for (auto &p : breakpoints) {
        code = ptrace(PTRACE_PEEKTEXT, child, p.addr, 0);
        if ((code & 0xff) != 0xcc)
            code = (code & ~0xff) | 0xcc;
        if(ptrace(PTRACE_POKETEXT, child, p.addr, code) != 0) errquit("ptrace(POKETEXT)");
    }
}

bool isNumber(const string& s) {
    return s.find_first_not_of("0123456789") == string::npos;
}

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

string help_message = ""
"- break {instruction-address}: add a break point\n"
"- cont: continue execution\n"
"- delete {break-point-id}: remove a break point\n"
"- disasm addr: disassemble instructions in a file or a memory region\n"
"- dump addr: dump memory content\n"
"- exit: terminate the debugger\n"
"- get reg: get a single value from a register\n"
"- getregs: show registers\n"
"- help: show this message\n"
"- list: list break points\n"
"- load {path/to/a/program}: load a program\n"
"- run: run the program\n"
"- vmmap: show memory layout\n"
"- set reg val: get a single value to a register\n"
"- si: step into instruction\n"
"- start: start the program and stop at the first instruction\n";