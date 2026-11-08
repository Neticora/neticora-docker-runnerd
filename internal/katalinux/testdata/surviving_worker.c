#define _GNU_SOURCE
#include <pthread.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Disposable child only. No host namespace or block device is mutated. */
static const char *target;
static int namespace_case;
static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return n == (ssize_t)strlen(data) ? 0 : -1;
}
static void *worker(void *unused) {
    (void)unused;
    if (namespace_case) {
        if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)) _exit(77);
        if (namespace_case == 2 && mount(target, target, NULL, MS_BIND, NULL)) _exit(77);
        if (mount("tmpfs", target, "tmpfs", MS_NOSUID|MS_NODEV, "size=1048576")) _exit(77);
    } else {
        int fd = open(target, O_RDWR);
        if (fd < 0) _exit(2);
        void *mapping = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mapping == MAP_FAILED) _exit(3);
        close(fd);
        ((volatile char *)mapping)[0] = 'x';
    }
    /* Publish readiness only after the leader really is a zombie. */
    char path[128], line[4096];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/stat", (long)getpid());
    for (int i=0; i<500; ++i) {
        FILE *f = fopen(path,"r");
        if (!f) _exit(4);
        if (!fgets(line,sizeof(line),f)) { fclose(f); _exit(5); }
        fclose(f);
        char *end = strrchr(line,')');
        if (end && end[1]==' ' && end[2]=='Z') {
            printf("READY %ld\n",syscall(SYS_gettid));
            fflush(stdout);
            for (;;) pause();
        }
        usleep(10000);
    }
    _exit(6);
}
int main(int argc, char **argv) {
    if (argc!=3) return 2;
    target=argv[2];namespace_case=!strcmp(argv[1],"namespace") ? 1 :
        (!strcmp(argv[1],"namespace-hidden-bind") ? 2 : 0);
    if (namespace_case) {
        uid_t uid=getuid();gid_t gid=getgid();
        if (unshare(CLONE_NEWUSER)) return 77;
        char map[80];
        if (write_file("/proc/self/setgroups","deny")) return 77;
        snprintf(map,sizeof(map),"0 %lu 1\n",(unsigned long)uid);
        if (write_file("/proc/self/uid_map",map)) return 77;
        snprintf(map,sizeof(map),"0 %lu 1\n",(unsigned long)gid);
        if (write_file("/proc/self/gid_map",map) || prctl(PR_SET_DUMPABLE,1)) return 77;
    }
    pthread_t thread;
    if (pthread_create(&thread,NULL,worker,NULL)) return 7;
    pthread_exit(NULL);
}
