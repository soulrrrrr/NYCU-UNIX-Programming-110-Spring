#include <iostream>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h> // isdigit()
#include <vector>
#include <string>
#include <fcntl.h> // open()
#include <unistd.h>
#include <sys/stat.h> // stat()
#include <fstream> // fstream
#include <pwd.h> // uid to username
#include <sstream>
#include <algorithm> // find(), sort()
#include <regex>
#include <errno.h>
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
void parse_mem(vector<info>&, info&, string);
void parse_fd(vector<info>&, info&, string);
string getuser(string);
string getfd(string, string);
string gettype(string);
string getnode(string);
void print_infos(vector<info>&, string, string, string);

int
main(int argc, char *argv[]) {
    /* parse arguments */
    string cc, tt, ff;
    for (int i = 1; i < argc; i += 2) {
        if (string(argv[i]) == "-c")
            cc = string(argv[i+1]);
        else if (string(argv[i]) == "-t") {
            tt = string(argv[i+1]); 
            if (tt != "REG" && tt != "CHR" && tt != "DIR" && tt != "FIFO" && tt != "SOCK" && tt != "unknown") {
                cout << "Invalid TYPE option." << endl;
                return 0;
            }
        }
        else if (string(argv[i]) == "-f")
            ff = string(argv[i+1]); 
    }
    ////
    printf("%-32s %-8s %-8s %-4s %-8s %-16s %s\n", 
        "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");
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
        if (inf.command == "broken")
            continue;
        inf.pid = proc_num;
        inf.user = getuser(s + "/status");
        open_read(infos, inf, s + "/cwd", "cwd");
        open_read(infos, inf, s + "/root", "rtd");
        open_read(infos, inf, s + "/exe", "txt");
        open_read(infos, inf, s + "/maps", "mem");
        open_read(infos, inf, s + "/fd", "fd");
    }
    print_infos(infos, cc, tt, ff);
    return 0;
}

string cat(string s) {
    int fd = open(s.c_str(), O_RDONLY);
    if (fd == -1 && errno == EACCES) {
        string ret = "broken";
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
        infos.push_back(inf);
    }
    else if (FD == "mem") {
        int fd = open(file.c_str(), O_RDONLY);
        if (fd < 0)
            return;
        close(fd);
        inf.fd = FD;
        inf.type = "REG";
        parse_mem(infos, inf, file);
    }
    else { // fd
        if((pdp = opendir(file.c_str())) == NULL) {
            inf.fd = "NOFD";
            inf.type = " ";
            inf.node = " ";
            inf.name = file + " (opendir: Permission denied)";
            infos.push_back(inf);
            return;
        }
        while ((pdirp = readdir(pdp)) != NULL) {
            if (!isdigit(pdirp->d_name[0]))
                continue; 
            string name = file+"/"+string(pdirp->d_name);
            inf.fd = getfd(file, string(pdirp->d_name));
            inf.type = gettype(name);
            inf.node = getnode(name);
            int read_size = readlink(name.c_str(), buf, BUF_SIZE);
            if (read_size > 0) {
                buf[read_size] = '\0';
                inf.name = string(buf);
                int found = inf.name.find(" (deleted)");
                if (found != std::string::npos) {
                    inf.name.replace(found, 10, "");
                }
            }
            infos.push_back(inf);
        }
        closedir(pdp);
    }
}

void parse_mem(vector<info> &infos, info &inf, string file) {
    fstream f(file.c_str(), std::fstream::in);
    string line;
    string tmp;
    vector<string> nodes;
    bool first = true;
    while(getline(f, line)) {
        stringstream ss(line);
        inf.fd = "mem";
        for (int i = 0; i < 5; i++) 
            ss >> tmp;
        if (tmp == "0") continue;
        if (find(nodes.begin(), nodes.end(), tmp) != nodes.end()) continue;
        nodes.push_back(tmp);
        inf.node = tmp;
        ss >> tmp;
        inf.name = tmp;
        int found = inf.name.find(" (deleted)");
        if (found != std::string::npos) {
            inf.fd = "DEL";
            inf.name.replace(found, 10, "");
        }
        if (first) {
            first = false;
            continue;
        }
        infos.push_back(inf);
    }
}

string getuser(string file) {
    fstream f(file.c_str(), std::fstream::in);
    string word;
    while (f >> word) {
        if (word == "Uid:") {
            f >> word;
            break;
        }
    }
    f.close();
    if (word.size() == 0 || !isdigit(word[0]))
        return "<deleted>";
    struct passwd *user_passwd = getpwuid(stoi(word));
    return string(user_passwd->pw_name);

}

string getfd(string file, string fd)  { // only for fd
    struct stat file_stat;
    string ret = "unknown";
    int per = 0;
    string name = file + "/" + fd;
    if (lstat(name.c_str(), &file_stat) < 0)
        return ret;
    if (file_stat.st_mode & S_IRWXU & S_IRUSR) {
       per += 2; 
    }
    if (file_stat.st_mode & S_IRWXU & S_IWUSR) {
       per += 1; 
    }
    string p;
    switch(per) {
        case 3:
            p = "u";
            break;
        case 2:
            p = "r";
            break;
        case 1:
            p = "w";
            break;
        default:
            p = "?";
            break;
    }
    return (fd + p);

    
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

void print_infos(vector<info>& infos, string cc, string tt, string ff) {
    std::smatch m;
    for (auto inf : infos) {
        if (!cc.empty()) {
            if (!regex_search(inf.command, m, regex(cc)))
                continue;
        }
        if (!tt.empty()) {
            if (inf.type != tt)
                continue;
        }
        if (!ff.empty()) {
            if (!regex_search(inf.name, m, regex(ff)))
                continue;
        }
        printf("%-32s %-8s %-8s %-4s %-8s %-16s %s\n", 
                inf.command.c_str(), 
                inf.pid.c_str(),
                inf.user.c_str(),
                inf.fd.c_str(),
                inf.type.c_str(),
                inf.node.c_str(),
                inf.name.c_str());
    }
}

