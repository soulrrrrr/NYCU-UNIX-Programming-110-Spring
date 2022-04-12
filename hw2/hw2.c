#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h> // ...
#include <fcntl.h> // __OPEN_NEEDS_MODE
#include <limits.h> // realpath()
#include <stdlib.h> // realpath()
#include <unistd.h> // chown(), close()
#include <string.h>
#include <ctype.h> // isprint()


#define MSG_SIZE 2048
#define PATH_SIZE 1024
#define PROCPATH_SIZE 512
char msg[MSG_SIZE];
char path[PATH_SIZE];
char procpath[PROCPATH_SIZE];

void logger_output();

void init() {
    memset(msg, 0, sizeof(msg));
    memset(path, 0, sizeof(path));
    memset(procpath, 0, sizeof(path));
}

int min(int a, int b) {
    if (a < b)
        return a;
    return b;
}

/* chmod */
static int (*old_chmod)(const char *, mode_t) = NULL;

int chmod(const char *pathname, mode_t mode) {
    init();
    if(old_chmod == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_chmod = dlsym(handle, "chmod");
    }
    int ret = -1;
    if(old_chmod != NULL) {
        ret = old_chmod(pathname, mode);
        realpath(pathname, path);
        sprintf(
            msg,
            "chmod(\"%s\", %03o) = %d",
            path,
            mode,
            ret);
        logger_output();
    }
    return ret;
}

/* chown */
static int (*old_chown)(const char *, uid_t, gid_t) = NULL;

int chown(const char *pathname, uid_t owner, gid_t group) {
    init();
    if(old_chown == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_chown = dlsym(handle, "chown");
    }
    int ret = -1;
    if(old_chown != NULL) {
        ret = old_chown(pathname, owner, group);
        realpath(pathname, path);
        sprintf(
            msg,
            "chown(\"%s\", %d, %d) = %d",
            path,
            owner,
            group,
            ret);
        logger_output();

    }
    return ret;
}

/* close */
static int (*old_close)(int) = NULL;

int close(int fd) {
    init();
    if(old_close == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_close = dlsym(handle, "close");
    }
    sprintf(procpath, "/proc/%d/fd/%d", getpid(), fd);
    readlink(procpath, path, PATH_SIZE);
    int ret = -1;
    if(old_close != NULL) {
        ret = old_close(fd);
        sprintf(
            msg,
            "close(\"%s\") = %d",
            path,
            ret);
        logger_output();
    }
    return ret;
}

/* creat */
static int (*old_creat)(const char *, mode_t) = NULL;

int creat(const char *pathname, mode_t mode) {
    init();
    if(old_creat == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_creat = dlsym(handle, "creat");
    }
    int ret = -1;
    if(old_creat != NULL) {
        ret = old_creat(pathname, mode);
        realpath(pathname, path);
        sprintf(
            msg,
            "creat(\"%s\", %03o) = %d",
            path,
            mode,
            ret);
        logger_output();
    }
    return ret;
}

/* creat64 */
static int (*old_creat64)(const char *, mode_t) = NULL;

int creat64(const char *pathname, mode_t mode) {
    init();
    if(old_creat64 == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_creat64 = dlsym(handle, "creat64");
    }
    int ret = -1;
    if(old_creat64 != NULL) {
        ret = old_creat64(pathname, mode);
        realpath(pathname, path);
        sprintf(
            msg,
            "creat64(\"%s\", %03o) = %d",
            path,
            mode,
            ret);
        logger_output();
    }
    return ret;
}

/* fclose */
static int (*old_fclose)(FILE *) = NULL;

int fclose(FILE *stream) {
    init();
    if(old_fclose == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fclose = dlsym(handle, "fclose");
    }
    sprintf(procpath, "/proc/%d/fd/%d", getpid(), fileno(stream));
    readlink(procpath, path, PATH_SIZE);
    int ret = -1;
    if(old_fclose != NULL) {
        ret = old_fclose(stream);
        sprintf(
            msg,
            "fclose(\"%s\") = %d",
            path,
            ret);
        logger_output();
    }
    return ret;
}

/* fopen */
static FILE *(*old_fopen)(const char *, const char *) = NULL;

FILE *fopen(const char *pathname, const char *mode) {
    init();
    if(old_fopen == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fopen = dlsym(handle, "fopen");
    }
    FILE *ret = NULL;
    if(old_fopen != NULL) {
        ret = old_fopen(pathname, mode);
        realpath(pathname, path);
        sprintf(
            msg,
            "fopen(\"%s\", \"%s\") = %p",
            path,
            mode,
            ret);
        logger_output();
    }
    return ret;
}

/* fopen64 */
static FILE *(*old_fopen64)(const char *, const char *) = NULL;

FILE *fopen64(const char *pathname, const char *mode) {
    init();
    if(old_fopen64 == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fopen64 = dlsym(handle, "fopen64");
    }
    FILE *ret = NULL;
    if(old_fopen64 != NULL) {
        ret = old_fopen64(pathname, mode);
        realpath(pathname, path);
        sprintf(
            msg,
            "fopen64(\"%s\", \"%s\") = %p",
            path,
            mode,
            ret);
        logger_output();
    }
    return ret;
}

/* fread */
static size_t (*old_fread)(void *, size_t, size_t, FILE *) = NULL;

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    init();
    if(old_fread == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fread = dlsym(handle, "fread");
    }
    size_t ret = 0;
    if(old_fread != NULL) {
        ret = old_fread(ptr, size, nmemb, stream);
        char buf[33] = {0};
        strncpy(buf, ptr, min(nmemb, 32));
        for (int i = 0; i < 32; i++) {
            if (buf[i] == '\0')
                break;
            else if (!isprint(buf[i]))
                buf[i] = '.';
        }
        sprintf(procpath, "/proc/%d/fd/%d", getpid(), fileno(stream));
        readlink(procpath, path, PATH_SIZE);
        sprintf(
            msg,
            "fread(\"%s\", %lu, %lu, \"%s\") = %ld",
            buf,
            size,
            nmemb,
            path,
            ret);
        logger_output();
    }
    return ret;
}


/* fwrite */
static size_t (*old_fwrite)(const void *, size_t, size_t, FILE *) = NULL;

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    init();
    if(old_fwrite == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fwrite = dlsym(handle, "fwrite");
    }
    size_t ret = 0;
    if(old_fwrite != NULL) {
        ret = old_fwrite(ptr, size, nmemb, stream);
        char buf[33] = {0};
        strncpy(buf, ptr, min(nmemb, 32));
        for (int i = 0; i < 32; i++) {
            if (buf[i] == '\0')
                break;
            else if (!isprint(buf[i]))
                buf[i] = '.';
        }
        sprintf(procpath, "/proc/%d/fd/%d", getpid(), fileno(stream));
        readlink(procpath, path, PATH_SIZE);
        sprintf(
            msg,
            "fwrite(\"%s\", %lu, %lu, \"%s\") = %ld",
            buf,
            size,
            nmemb,
            path,
            ret);
        logger_output();
    }
    return ret;
}

/* open */
static int (*old_open)(const char *, int, ...) = NULL;

int open(const char *pathname, int flags, ...) {
    init();
    // https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/open.c.html
    mode_t mode = 0;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }

    if(old_open == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_open = dlsym(handle, "open");
    }
    int ret = -1;
    if(old_open != NULL) {
        ret = old_open(pathname, flags, mode);
        realpath(pathname, path);
        sprintf(
            msg,
            "open(\"%s\", %03o, %03o) = %d",
            path,
            flags,
            mode,
            ret);
        logger_output();
    }
    return ret;
}

/* open64 */
static int (*old_open64)(const char *, int, ...) = NULL;

int open64(const char *pathname, int flags, ...) {
    init();
    // https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/open.c.html
    mode_t mode = 0;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }

    if(old_open64 == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_open64 = dlsym(handle, "open64");
    }
    int ret = -1;
    if(old_open64 != NULL) {
        ret = old_open64(pathname, flags, mode);
        realpath(pathname, path);
        sprintf(
            msg,
            "open64(\"%s\", %03o, %03o) = %d",
            path,
            flags,
            mode,
            ret);
        logger_output();
    }
    return ret;
}

/* read */
static ssize_t (*old_read)(int, void *, size_t) = NULL;

ssize_t read(int fd, void *buf, size_t count) {
    init();
    if(old_read == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_read = dlsym(handle, "read");
    }
    ssize_t ret = 0;
    if(old_read != NULL) {
        ret = old_read(fd, buf, count);
        char buff[33] = {0}; // buf is already used
        strncpy(buff, buf, min(count, 32));
        for (int i = 0; i < 32; i++) {
            if (buff[i] == '\0')
                break;
            else if (!isprint(buff[i]))
                buff[i] = '.';
        }
        sprintf(procpath, "/proc/%d/fd/%d", getpid(), fd);
        readlink(procpath, path, PATH_SIZE);
        sprintf(
            msg,
            "read(\"%s\", \"%s\", %lu) = %ld",
            path,
            buff,
            count,
            ret);
        logger_output();
    }
    return ret;
}


/* remove */
static int (*old_remove)(const char *) = NULL;

int remove(const char *pathname) {
    init();
    if(old_remove == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_remove = dlsym(handle, "remove");
    }
    int ret = -1;
    if(old_remove != NULL) {
        realpath(pathname, path);
        ret = old_remove(pathname);
        sprintf(
            msg,
            "remove(\"%s\") = %d",
            path,
            ret);
        logger_output();
    }
    return ret;
}

/* tmpfile */
static FILE *(*old_tmpfile)(void) = NULL;

FILE *tmpfile(void) {
    init();
    if(old_tmpfile == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_tmpfile = dlsym(handle, "tmpfile");
    }
    FILE *ret = NULL;
    if(old_tmpfile != NULL) {
        ret = old_tmpfile();
        sprintf(
            msg,
            "tmpfile() = %p",
            ret);
        logger_output();
    }
    return ret;
}

/* tmpfile64 */
static FILE *(*old_tmpfile64)(void) = NULL;

FILE *tmpfile64(void) {
    init();
    if(old_tmpfile64 == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_tmpfile64 = dlsym(handle, "tmpfile64");
    }
    FILE *ret = NULL;
    if(old_tmpfile64 != NULL) {
        ret = old_tmpfile64();
        sprintf(
            msg,
            "tmpfile64() = %p",
            ret);
        logger_output();
    }
    return ret;
}

/* write */
static ssize_t (*old_write)(int, const void *, size_t) = NULL;

ssize_t write(int fd, const void *buf, size_t count) {
    init();
    if(old_write == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_write = dlsym(handle, "write");
    }
    ssize_t ret = 0;
    if(old_write != NULL) {
        ret = old_write(fd, buf, count);
        char buff[33] = {0}; // buf is already used
        strncpy(buff, buf, min(count, 32));
        for (int i = 0; i < 32; i++) {
            if (buff[i] == '\0')
                break;
            else if (!isprint(buff[i]))
                buff[i] = '.';
        }
        sprintf(procpath, "/proc/%d/fd/%d", getpid(), fd);
        readlink(procpath, path, PATH_SIZE);
        sprintf(
            msg,
            "write(\"%s\", \"%s\", %lu) = %ld",
            path,
            buff,
            count,
            ret);
        logger_output();
    }
    return ret;
}

void logger_output() {
    if(old_fopen == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fopen = dlsym(handle, "fopen");
    }
    if(old_fclose == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            old_fclose = dlsym(handle, "fclose");
    }
    dprintf(3, "[logger] %s\n", msg);
}
