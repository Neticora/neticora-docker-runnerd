#define _GNU_SOURCE
#include <pthread.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Qualification-only worker. It enters the owned slice before executing, then
 * retains a surviving thread which repeatedly acquires an original O_PATH handle.
 * The progress file belongs solely to the fresh private fixture. */
static const char *target;
static void *worker(void *unused) {
    (void)unused;
    char path[4096], leader[128], state[4096];
    if (snprintf(path, sizeof(path), "%s.progress", target) >= (int)sizeof(path)) _exit(2);
    int progress = open(path, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0600);
    if (progress < 0) _exit(3);
    snprintf(leader, sizeof(leader), "/proc/self/task/%ld/stat", (long)getpid());
    for (int i=0; i<500; i++) {
        FILE *f=fopen(leader,"r");
        if (!f || !fgets(state,sizeof(state),f)) _exit(4);
        fclose(f);
        char *end=strrchr(state,')');
        if (end && end[1]==' ' && end[2]=='Z') break;
        if (i==499) _exit(5);
        usleep(10000);
    }
    unsigned long count=0;
    for (;;) {
        int fd=open(target,O_PATH|O_CLOEXEC);
        if (fd<0) _exit(6);
        close(fd);
        char value[32];
        int size=snprintf(value,sizeof(value),"%020lu\n",++count);
        if (pwrite(progress,value,(size_t)size,0)!=size) _exit(7);
        if (count==100) { printf("READY %ld\n",syscall(SYS_gettid)); fflush(stdout); }
    }
}
int main(int argc,char **argv) {
    if (argc!=3 || strcmp(argv[1],"acquire")) return 2;
    target=argv[2];
    pthread_t thread;
    if (pthread_create(&thread,NULL,worker,NULL)) return 8;
    pthread_exit(NULL);
}
