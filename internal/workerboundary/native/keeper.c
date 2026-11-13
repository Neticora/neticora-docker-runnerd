#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Root-owned namespace init, not an authorization service. The broker binds its
 * host PID/start/boot and PID/mount namespace inodes BEFORE granting RUN access.
 * A sender in this namespace or a descendant has a visible positive peer PID and
 * cannot invoke this supervisor, even if its uid is zero. External root remains
 * trusted. The socket lives in the broker's protected per-execution directory.
 * No task is ever moved, adopted or killed by a caller-supplied PID. */
#define LIMIT 65536
#define ARGS 128
#define ERROR_EXIT 125

static int all_write(int fd, const void *data, size_t size) {
    const char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; size -= (size_t)n;
    }
    return 0;
}

#define DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (n), 0, 1), \
                BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM)

/* No pointer inspection and no USER_NOTIF CONTINUE. Deny the complete kernel
 * descriptor-transfer entry points, including asynchronous/compat alternatives.
 * The restriction is irreversible and inherited across fork/exec. Ordinary
 * write/writev/sendto byte streams remain available. Compatibility must be
 * qualified; a runtime requiring sendmsg is rejected, not silently exempted. */
static int restrict_worker(void) {
#if !defined(__x86_64__)
#error qualified architecture is amd64 only
#endif
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        DENY(__NR_sendmsg), DENY(__NR_sendmmsg),
        DENY(__NR_io_uring_setup), DENY(__NR_io_uring_register), DENY(__NR_io_uring_enter),
        DENY(__NR_ptrace), DENY(__NR_process_vm_readv), DENY(__NR_process_vm_writev),
        DENY(__NR_pidfd_getfd), DENY(__NR_bpf), DENY(__NR_perf_event_open),
        /* clone3's pointer-based CLONE_INTO_CGROUP cannot bypass this policy.
         * ENOSYS permits libc's ordinary clone fallback, which inherits the ns. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|ENOSYS),
        /* Explicit mount/net/user namespace operations can remain inside this
         * PID lifetime boundary. Zero/inferred or PID setns is forbidden. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_setns, 0, 6),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 3, 0),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, CLONE_NEWPID, 2, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        /* A worker cannot make a changed-credential process dumpable to an
         * external nonroot peer after creating a user namespace. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_prctl, 0, 5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PR_SET_DUMPABLE, 0, 3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(filter)/sizeof(filter[0]), .filter = filter};
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program)) return -1;
    return 0;
}

static void reply(int socket, int status) {
    int32_t value = status;
    (void)all_write(socket, &value, sizeof(value));
}

static int enter_profile(const char *profile) {
    /* No unconfined fallback. A separately reviewed native fixture can supply
     * its own narrow enforcing profile; the actual label is independently read
     * by the broker before treating any worker placement as qualified. */
    if (!profile || !*profile || strchr(profile, '\n') || strlen(profile) > 128) return -1;
    int fd = open("/proc/self/attr/exec", O_WRONLY|O_CLOEXEC);
    if (fd < 0) return -1;
    char text[160];
    int length = snprintf(text, sizeof(text), "exec %s", profile);
    int result = all_write(fd, text, (size_t)length);
    close(fd);
    return result;
}

static void run_child(int client, char *request, size_t size, int *fds, size_t count,
                      int listener, const char *profile) {
    if (count != 3 || size < 6 || memcmp(request, "RUN\0", 4) || request[size-1]) {
        reply(client, ERROR_EXIT); return;
    }
    char *argv[ARGS]; size_t argc = 0, offset = 4;
    while (offset < size && argc < ARGS-1) {
        size_t length = strnlen(request+offset, size-offset);
        if (!length || length == size-offset) { reply(client, ERROR_EXIT); return; }
        argv[argc++] = request+offset; offset += length+1;
    }
    if (offset != size || !argc || argv[0][0] != '/') { reply(client, ERROR_EXIT); return; }
    argv[argc] = NULL;
    pid_t child = fork();
    if (child < 0) { reply(client, ERROR_EXIT); return; }
    if (!child) {
        close(listener); close(client);
        for (int i=0; i<3; i++) if (dup2(fds[i], i) < 0) _exit(ERROR_EXIT);
        /* No namespace, cgroup, pidfd, io_uring or control descriptor survives. */
        if (syscall(SYS_close_range, 3U, ~0U, 0)) _exit(ERROR_EXIT);
        if (enter_profile(profile) || restrict_worker()) _exit(ERROR_EXIT);
        execv(argv[0], argv);
        _exit(ERROR_EXIT);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) { reply(client, ERROR_EXIT); return; }
    reply(client, WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status));
}

int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "init") || getpid() != 1 || getuid() || geteuid()) return ERROR_EXIT;
    const char *path = argv[2], *profile = argv[3];
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path) || path[0] != '/') return ERROR_EXIT;
    umask(0077);
    if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) ||
        umount2("/proc", MNT_DETACH) ||
        mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)) return ERROR_EXIT;
    /* The parent deliberately supplies no inherited descriptor above stdio. */
    if (syscall(SYS_close_range, 3U, ~0U, 0)) return ERROR_EXIT;
    int listener = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
    if (listener < 0) return ERROR_EXIT;
    struct sockaddr_un address = {.sun_family=AF_UNIX};
    memcpy(address.sun_path, path, strlen(path)+1);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || chmod(path, 0600) || listen(listener, 8)) return ERROR_EXIT;
    for (;;) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {}
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) { if (errno==EINTR) continue; return ERROR_EXIT; }
        struct ucred peer; socklen_t length = sizeof(peer);
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &length) ||
            length != sizeof(peer) || peer.uid || peer.pid != 0) {
            reply(client, ERROR_EXIT); close(client); continue;
        }
        char request[LIMIT], ancillary[CMSG_SPACE(3*sizeof(int))];
        struct iovec data = {.iov_base=request, .iov_len=sizeof(request)};
        struct msghdr msg = {.msg_iov=&data, .msg_iovlen=1,
            .msg_control=ancillary, .msg_controllen=sizeof(ancillary)};
        ssize_t size = recvmsg(client, &msg, MSG_CMSG_CLOEXEC);
        int fds[3]; size_t count=0; int bad=0;
        for (struct cmsghdr *c=CMSG_FIRSTHDR(&msg); c; c=CMSG_NXTHDR(&msg,c)) {
            if (c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS || c->cmsg_len<CMSG_LEN(0)) { bad=1; continue; }
            size_t bytes=c->cmsg_len-CMSG_LEN(0);
            if (bytes%sizeof(int)) { bad=1; continue; }
            for (size_t i=0;i<bytes/sizeof(int);i++) {
                int fd; memcpy(&fd,(char *)CMSG_DATA(c)+i*sizeof(int),sizeof(fd));
                if (count<3) fds[count++]=fd; else {close(fd);bad=1;}
            }
        }
        if (size<=0 || bad || msg.msg_flags&(MSG_CTRUNC|MSG_TRUNC)) reply(client, ERROR_EXIT);
        else if (size==5 && !memcmp(request,"STOP\0",5) && !count) {
            /* Namespace-init exit synchronously retires all descendants in the
             * kernel, including descendants moved to another host cgroup. The
             * broker waits on its original pidfd before asserting retirement. */
            close(client); close(listener); _exit(0);
        } else run_child(client,request,(size_t)size,fds,count,listener,profile);
        for (size_t i=0;i<count;i++) close(fds[i]);
        close(client);
    }
}
