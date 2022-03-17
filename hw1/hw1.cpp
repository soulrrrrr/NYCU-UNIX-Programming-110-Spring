#include <iostream>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h> // isdigit()
#include <vector>
#include <string>
#include <fcntl.h> // open()
#include <unistd.h>
#include <sys/stat.h> // stat()
#define BUF_SIZE 1024
using namespace std;

struct info{
    string command;
    string pid;
    string user;
    string fd;
    string type;
    string node;
    string name;
};

string cat(string);
void open_read(vector<info>&, info&, string, string);
string getuser(string);
string gettype(string);
string getnode(string);
void print_infos(vector<info>&);

int
main(int argc, char *argv[]) {
    printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");
    fflush(stdout);
    DIR *dp;
    dirent *dirp;
    if((dp = opendir("/proc")) == NULL) {
        cout << "error open /proc" << endl;
        return 0;
    }
    vector<string> procs;
    while ((dirp = readdir(dp)) != NULL) {
        if (isdigit(dirp->d_name[0]))
            procs.push_back(string(dirp->d_name));
    }
    closedir(dp);
    vector<info> infos;
    for (auto proc_num : procs) {
        string s = "/proc/" + proc_num;
        info inf;
        inf.command = cat(s + "/comm");
        inf.pid = proc_num;
        //inf.user = getuser(inf, s + "/status");
        open_read(infos, inf, s + "/cwd", "cwd");
        open_read(infos, inf, s + "/root", "rtd");
        open_read(infos, inf, s + "/exe", "txt");
        //open_read(infos, inf, s + "/maps", "mem");
        //open_read(infos, inf, s + "/fd", "fd");
    }
    print_infos(infos);
    return 0;
}

string cat(string s) {
    int fd = open(s.c_str(), O_RDONLY);
    if (fd == -1) {
        string ret = s + " (can't open maps: Permission denied)";
        return ret;
    }
    char buf[BUF_SIZE];
    int read_size = read(fd, buf, BUF_SIZE);
    buf[read_size-1] = '\0';
    close(fd);
    return string(buf);
}

void open_read(vector<info> &infos, info &inf, string file, string FD) {
    DIR *pdp; //proc dir pointer
    dirent *pdirp;
    char buf[BUF_SIZE];
    if (FD == "cwd" || FD == "rtd" || FD == "txt") {
        inf.fd = FD;
        inf.type = gettype(file);
        inf.node = getnode(file);
        int read_size = readlink(file.c_str(), buf, BUF_SIZE);
        if (read_size > 0) {
            buf[read_size] = '\0';
            inf.name = string(buf);
        }
        else {
            inf.name = file + " (readlink: Permission denied)";
        }
    }
    else if (FD == "mem") {
        inf.fd = FD;
        cat(FD);
    }
    else { // fd
        if((pdp = opendir(file.c_str())) == NULL) {
            cout << "error open" << file << endl;
            return;
        }
        while ((pdirp = readdir(pdp)) != NULL) {
            cout << pdirp->d_name << endl; 
        }
    }
    infos.push_back(inf);
    //while ((pdirp = readdir(pdp)) != NULL) {
    //    printf("%s\n", pdirp->d_name);
    //}
}

string gettype(string file) {
    struct stat file_stat;
    string ret = "unknown";
    if (stat(file.c_str(), &file_stat) < 0)
        return ret;
    switch(file_stat.st_mode & S_IFMT) {
        case S_IFDIR:
            ret = "DIR";
            break;
        case S_IFREG:
            ret = "REG";
            break;
        case S_IFCHR:
            ret = "CHR";
            break;
        case S_IFIFO:
            ret = "FIFO";
            break;
        case S_IFSOCK:
            ret = "SOCK";
            break;
        default:
            break;
    }
    return ret;
}

string getnode(string file) {
    struct stat file_stat;
    if (stat(file.c_str(), &file_stat) < 0)
        return " ";
    return to_string(file_stat.st_ino);
}

void print_infos(vector<info>& infos) {
    for (auto inf : infos) {
        printf("%-32s %-8s %-8s %-16s %s\n", 
                inf.command.c_str(), 
                inf.pid.c_str(),
                inf.type.c_str(),
                inf.node.c_str(),
                inf.name.c_str());
    }
}

