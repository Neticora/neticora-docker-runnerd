#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
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
#define BOOTSTRAP_FD 198
#define TRANSFER_BYTES (1024U*1024U)
#define TRANSFER_FDS 64

static void reply(int socket,int status);

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

/* sendmsg is emulated from private copies and captured file descriptions, never
 * resumed with CONTINUE. Alternate transfer APIs remain denied. The sole
 * bootstrap exemption is irreversibly sealed before executing any worker. */
static int restrict_worker(void) {
#if !defined(__x86_64__)
#error qualified architecture is amd64 only
#endif
    /* Namespace/mount/network privileges needed by the runtime are qualified
     * separately. Workers must never gain kernel-module, policy-administration
     * or cross-process-injection authority that could remove this boundary. */
    const int drop[] = {CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_PTRACE, CAP_SYS_BOOT,
        CAP_MAC_ADMIN, CAP_MAC_OVERRIDE, CAP_SYSLOG, CAP_SETPCAP,
        CAP_BPF, CAP_PERFMON, CAP_CHECKPOINT_RESTORE,
        CAP_AUDIT_CONTROL, CAP_AUDIT_WRITE, CAP_AUDIT_READ};
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct caps[2];
    if (syscall(SYS_capget, &header, caps) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) return -1;
    for (size_t i=0;i<sizeof(drop)/sizeof(drop[0]);i++) {
        if (prctl(PR_CAPBSET_DROP, drop[i], 0, 0, 0)) return -1;
        unsigned index=(unsigned)drop[i]/32, bit=1U<<((unsigned)drop[i]%32);
        caps[index].effective &= ~bit;
        caps[index].permitted &= ~bit;
        caps[index].inheritable &= ~bit;
    }
    if (syscall(SYS_capset, &header, caps)) return -1;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_sendmsg, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, BOOTSTRAP_FD, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF),
        DENY(__NR_sendmmsg),
        DENY(__NR_io_uring_setup), DENY(__NR_io_uring_register), DENY(__NR_io_uring_enter),
        DENY(__NR_ptrace), DENY(__NR_process_vm_readv), DENY(__NR_process_vm_writev),
        DENY(__NR_pidfd_getfd), DENY(__NR_bpf), DENY(__NR_perf_event_open),
        DENY(__NR_init_module), DENY(__NR_finit_module), DENY(__NR_delete_module),
        DENY(__NR_kexec_load), DENY(__NR_kexec_file_load),
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
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
}

static int seal_bootstrap(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_sendmsg, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, BOOTSTRAP_FD, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        /* A newer USER_NOTIF listener could otherwise override this one.
         * Ordinary additional sandbox filters may only restrict the worker. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_seccomp, 0, 3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, SECCOMP_FILTER_FLAG_NEW_LISTENER, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program={.len=sizeof(filter)/sizeof(filter[0]),.filter=filter};
    return syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program);
}

static int remote_copy(pid_t tid, void *out, uint64_t address, size_t size) {
    if (!size) return 0;
    if (!address || address+size<address) return -1;
    struct iovec local={.iov_base=out,.iov_len=size};
    struct iovec remote={.iov_base=(void *)(uintptr_t)address,.iov_len=size};
    return process_vm_readv(tid,&local,1,&remote,1,0)==(ssize_t)size?0:-1;
}

static int transferable(int fd) {
    struct stat s; struct statfs fs;
    if(fstat(fd,&s)||fstatfs(fd,&fs))return 0;
    /* Socket endpoints cannot be delegated: their peer credentials describe
     * connection establishment, not a later recipient of a passed endpoint. */
    if(S_ISSOCK(s.st_mode))return 0;
    if(S_ISREG(s.st_mode)||S_ISDIR(s.st_mode)||S_ISFIFO(s.st_mode)) {
        switch((unsigned long)fs.f_type) {
        case PROC_SUPER_MAGIC: case SYSFS_MAGIC: case CGROUP_SUPER_MAGIC:
        case CGROUP2_SUPER_MAGIC: case BPF_FS_MAGIC: case NSFS_MAGIC:
        case SECURITYFS_MAGIC: case DEBUGFS_MAGIC: case TRACEFS_MAGIC:return 0;
        default:return 1;
        }
    }
    char path[64],target[128];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(path,target,sizeof(target)-1);
    if(n<0)return 0;
    target[n]=0;
    return !strcmp(target,"anon_inode:[eventfd]");
}

static ssize_t emulate_sendmsg(int listener,const struct seccomp_notif *request) {
    int thread=-1,socket=-1,held[TRANSFER_FDS],count=0,error=EPERM;
    ssize_t result=-1; void *payload=NULL;
    struct msghdr remote,message={0};struct iovec vectors[128],data={0};
    unsigned char control[4096],rebuilt[CMSG_SPACE(TRANSFER_FDS*sizeof(int))];
    int flags=(int)request->data.args[2];
    if(request->data.nr!=__NR_sendmsg||request->data.arch!=AUDIT_ARCH_X86_64||
       request->data.args[0]>INT32_MAX||
       flags&~(MSG_DONTWAIT|MSG_NOSIGNAL|MSG_MORE|MSG_EOR)||
       ioctl(listener,SECCOMP_IOCTL_NOTIF_ID_VALID,&request->id))goto done;
    /* PIDFD_THREAD is mandatory. A thread may own a different file table from
     * its group leader; substituting the leader would validate the wrong FD. */
    thread=syscall(SYS_pidfd_open,request->pid,O_EXCL);
    if(thread<0)goto done;
    if(ioctl(listener,SECCOMP_IOCTL_NOTIF_ID_VALID,&request->id))goto done;
    socket=syscall(SYS_pidfd_getfd,thread,(int)request->data.args[0],0);
    if(socket<0||remote_copy(request->pid,&remote,request->data.args[1],sizeof(remote)))goto done;
    if(remote.msg_name||remote.msg_namelen||remote.msg_iovlen>128||remote.msg_controllen>sizeof(control))goto done;
    if(remote_copy(request->pid,vectors,(uintptr_t)remote.msg_iov,remote.msg_iovlen*sizeof(vectors[0]))||
       remote_copy(request->pid,control,(uintptr_t)remote.msg_control,remote.msg_controllen))goto done;
    size_t total=0;
    for(size_t i=0;i<remote.msg_iovlen;i++) {
        if(vectors[i].iov_len>TRANSFER_BYTES-total)goto done;
        total+=vectors[i].iov_len;
    }
    payload=malloc(total?total:1);if(!payload){error=ENOMEM;goto done;}
    size_t offset=0;
    for(size_t i=0;i<remote.msg_iovlen;i++) {
        if(remote_copy(request->pid,(char *)payload+offset,(uintptr_t)vectors[i].iov_base,vectors[i].iov_len))goto done;
        offset+=vectors[i].iov_len;
    }
    /* Parse ONLY our copied ancillary bytes. Never let libc walk remote data. */
    offset=0;
    while(offset<remote.msg_controllen) {
        if(remote.msg_controllen-offset<sizeof(struct cmsghdr))goto done;
        struct cmsghdr c;memcpy(&c,control+offset,sizeof(c));
        if(c.cmsg_len<CMSG_LEN(0)||c.cmsg_len>remote.msg_controllen-offset||
           c.cmsg_level!=SOL_SOCKET||c.cmsg_type!=SCM_RIGHTS)goto done;
        size_t bytes=c.cmsg_len-CMSG_LEN(0);
        if(!bytes||bytes%sizeof(int)||bytes/sizeof(int)>(size_t)(TRANSFER_FDS-count))goto done;
        for(size_t i=0;i<bytes/sizeof(int);i++) {
            int original;memcpy(&original,control+offset+CMSG_LEN(0)+i*sizeof(int),sizeof(original));
            if(original<0)goto done;
            int fd=syscall(SYS_pidfd_getfd,thread,original,0);
            if(fd<0)goto done;
            held[count++]=fd;
            if(!transferable(fd))goto done;
        }
        size_t next=CMSG_ALIGN(c.cmsg_len);
        if(next>remote.msg_controllen-offset) {
            if(c.cmsg_len!=remote.msg_controllen-offset)goto done;
            offset=remote.msg_controllen;
        }else offset+=next;
    }
    if(count) {
        struct ucred peer;int type,domain;socklen_t length=sizeof(peer),n=sizeof(int);
        if(getsockopt(socket,SOL_SOCKET,SO_DOMAIN,&domain,&n)||domain!=AF_UNIX)goto done;
        n=sizeof(int);
        if(getsockopt(socket,SOL_SOCKET,SO_TYPE,&type,&n)||(type!=SOCK_STREAM&&type!=SOCK_SEQPACKET))goto done;
        /* Ancestor/outside peers have PID zero in this ORIGINAL namespace.
         * A connected stream peer is immutable; socket FD relay is forbidden. */
        if(getsockopt(socket,SOL_SOCKET,SO_PEERCRED,&peer,&length)||length!=sizeof(peer)||peer.pid<=0)goto done;
        memset(rebuilt,0,sizeof(rebuilt));
        message.msg_control=rebuilt;message.msg_controllen=CMSG_SPACE((size_t)count*sizeof(int));
        struct cmsghdr *c=CMSG_FIRSTHDR(&message);
        c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN((size_t)count*sizeof(int));
        memcpy(CMSG_DATA(c),held,(size_t)count*sizeof(int));
    }
    data.iov_base=payload;data.iov_len=total;message.msg_iov=&data;message.msg_iovlen=1;
    if(ioctl(listener,SECCOMP_IOCTL_NOTIF_ID_VALID,&request->id))goto done;
    /* Captured socket, captured FDs and copied buffers only. Never CONTINUE.
     * Nonblocking emulation bounds guardian latency; compatibility is qualified
     * separately and cannot weaken the outward-recipient check. */
    result=sendmsg(socket,&message,flags|MSG_NOSIGNAL|MSG_DONTWAIT);error=errno;
done:
    if(socket>=0)close(socket);
    if(thread>=0)close(thread);
    for(int i=0;i<count;i++)close(held[i]);
    free(payload);errno=error;return result;
}

static int receive_listener(int bootstrap) {
    char byte=0,control[CMSG_SPACE(sizeof(int))]={0};struct iovec data={.iov_base=&byte,.iov_len=1};
    struct msghdr message={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    if(recvmsg(bootstrap,&message,MSG_CMSG_CLOEXEC)!=1||byte!='L'||message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))return -1;
    struct cmsghdr *c=CMSG_FIRSTHDR(&message);
    if(!c||c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS||c->cmsg_len!=CMSG_LEN(sizeof(int)))return -1;
    int fd;memcpy(&fd,CMSG_DATA(c),sizeof(fd));return fd;
}

static void supervise_transfers(int listener,pid_t child,int client) {
    int replied=0;
    for(;;) {
        if(!replied) {
            int status;pid_t ready=waitpid(child,&status,WNOHANG);
            if(ready==child) {
                reply(client,WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
                close(client);replied=1;
            }else if(ready<0)break;
        }
        struct pollfd event={.fd=listener,.events=POLLIN};
        int n=poll(&event,1,20);
        if(n<0){if(errno==EINTR)continue;break;}
        if(event.revents&POLLIN) {
            struct seccomp_notif request={0};
            if(ioctl(listener,SECCOMP_IOCTL_NOTIF_RECV,&request)) {
                if(errno==EINTR||errno==ENOENT)continue;
                break;
            }
            ssize_t value=emulate_sendmsg(listener,&request);
            struct seccomp_notif_resp response={.id=request.id,.val=value<0?0:value,.error=value<0?-errno:0};
            if(ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&response)&&errno!=ENOENT)break;
        }
        if(event.revents&POLLHUP) {
            /* The last filtered task can exit between WNOHANG and poll. Reap
             * that original child instead of converting successful completion
             * into a supervisor error. No live filtered task remains at HUP. */
            if(!replied) {
                int status;pid_t ready;
                do{ready=waitpid(child,&status,0);}while(ready<0&&errno==EINTR);
                if(ready==child) {
                    reply(client,WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
                    replied=1;
                }
            }
            break;
        }
        if(event.revents&(POLLERR|POLLNVAL))break;
    }
    if(!replied)reply(client,ERROR_EXIT);
    close(listener);
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

static int safe_stdio(int fd) {
    struct stat s; struct statfs fs;
    int flags = fcntl(fd,F_GETFL);
    if (flags < 0 || flags&O_PATH || fstat(fd,&s) || fstatfs(fd,&fs)) return 0;
    if (S_ISCHR(s.st_mode)) return major(s.st_rdev)==1 && minor(s.st_rdev)==3;
    if (!S_ISREG(s.st_mode) && !S_ISFIFO(s.st_mode)) return 0;
    switch ((unsigned long)fs.f_type) {
    case PROC_SUPER_MAGIC: case SYSFS_MAGIC: case CGROUP_SUPER_MAGIC:
    case CGROUP2_SUPER_MAGIC: case BPF_FS_MAGIC: case NSFS_MAGIC:
    case SECURITYFS_MAGIC: case DEBUGFS_MAGIC: case TRACEFS_MAGIC:
        return 0;
    default: return 1;
    }
}

static void run_child(int client, char *request, size_t size, int *fds, size_t count,
                      int listener, const char *profile) {
    if (count != 3 || size < 6 || memcmp(request, "RUN\0", 4) || request[size-1]) {
        reply(client, ERROR_EXIT); return;
    }
    for (size_t i=0;i<count;i++) if (!safe_stdio(fds[i])) { reply(client,ERROR_EXIT); return; }
    char *argv[ARGS]; size_t argc = 0, offset = 4;
    while (offset < size && argc < ARGS-1) {
        size_t length = strnlen(request+offset, size-offset);
        if (!length || length == size-offset) { reply(client, ERROR_EXIT); return; }
        argv[argc++] = request+offset; offset += length+1;
    }
    if (offset != size || !argc || argv[0][0] != '/') { reply(client, ERROR_EXIT); return; }
    argv[argc] = NULL;
    int bootstrap[2];
    if(prctl(PR_SET_DUMPABLE,0,0,0,0)||socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,bootstrap)) {
        reply(client,ERROR_EXIT);return;
    }
    pid_t child = fork();
    if (child < 0) {close(bootstrap[0]);close(bootstrap[1]);reply(client, ERROR_EXIT); return; }
    if (!child) {
        close(bootstrap[0]);
        close(listener); close(client);
        for (int i=0; i<3; i++) if (dup2(fds[i], i) < 0) _exit(ERROR_EXIT);
        if(dup2(bootstrap[1],BOOTSTRAP_FD)<0||
           syscall(SYS_close_range,3U,BOOTSTRAP_FD-1,0)||
           syscall(SYS_close_range,BOOTSTRAP_FD+1,~0U,0)||enter_profile(profile))_exit(ERROR_EXIT);
        int notifications=restrict_worker();
        if(notifications<0)_exit(ERROR_EXIT);
        char byte='L',control[CMSG_SPACE(sizeof(int))]={0};
        struct iovec data={.iov_base=&byte,.iov_len=1};
        struct msghdr message={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        struct cmsghdr *c=CMSG_FIRSTHDR(&message);
        c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&notifications,sizeof(notifications));
        if(sendmsg(BOOTSTRAP_FD,&message,MSG_NOSIGNAL)!=1||seal_bootstrap())_exit(ERROR_EXIT);
        close(notifications);
        if(read(BOOTSTRAP_FD,&byte,1)!=1||byte!='R')_exit(ERROR_EXIT);
        close(BOOTSTRAP_FD);
        /* No namespace, cgroup, pidfd, notifier or bootstrap descriptor survives. */
        execv(argv[0], argv);
        _exit(ERROR_EXIT);
    }
    close(bootstrap[1]);
    int notifications=receive_listener(bootstrap[0]);
    /* Isolate the monitor's /proc before any untrusted exec. A worker with
     * mount authority must not replace the monitor's descriptor-inspection
     * filesystem. Both remain descendants of the original PID namespace. */
    if(notifications<0||unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
       all_write(bootstrap[0],"R",1)) {
        if(notifications>=0)close(notifications);
        close(bootstrap[0]);reply(client,ERROR_EXIT);return;
    }
    close(bootstrap[0]);
    supervise_transfers(notifications,child,client);
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
        } else {
            /* A worker may block on a denied control request. Keep PID1's
             * peer checks and retirement control responsive while a trusted
             * request handler waits for that worker. Handlers remain inside
             * the same kernel lifetime boundary and never execute user code. */
            pid_t handler = fork();
            if (handler < 0) reply(client, ERROR_EXIT);
            else if (!handler) {
                run_child(client,request,(size_t)size,fds,count,listener,profile);
                for (size_t i=0;i<count;i++) close(fds[i]);
                close(client); close(listener); _exit(0);
            }
        }
        for (size_t i=0;i<count;i++) close(fds[i]);
        close(client);
    }
}
