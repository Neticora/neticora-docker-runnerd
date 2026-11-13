#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/loop.h>
#include <sched.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Component experiment only. No recursive deletion, erasure, admission or
 * journal integration. Every filesystem/device used here is a fresh fixture. */
#define REQUIRE(condition) do { if (!(condition)) { \
    fprintf(stderr, "inconclusive/failed prototype assertion at line %d: %s (errno=%d)\n", \
            __LINE__, #condition, errno); exit(2); } } while (0)

static const char *device;
static char base[PATH_MAX], alias[PATH_MAX], target[PATH_MAX], alias_target[PATH_MAX];
static struct stat original;
static unsigned cases;

static void join(char *out, const char *parent, const char *name)
{
    size_t a = strlen(parent), b = strlen(name);
    REQUIRE(a + b + 2 <= PATH_MAX);
    memcpy(out, parent, a);
    out[a] = '/';
    memcpy(out + a + 1, name, b + 1);
}

static int same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static void mount_base(void)
{
    REQUIRE(mount(device, base, "ext4", MS_NODEV | MS_NOSUID, "") == 0);
}

static void preserved(void)
{
    struct stat current;
    REQUIRE(lstat(target, &current) == 0 && same(&original, &current));
    REQUIRE(current.st_nlink == 1);
    int fd = open(target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char content[64] = {0};
    REQUIRE(fd >= 0);
    REQUIRE(read(fd, content, sizeof(content)) > 0);
    REQUIRE(!strcmp(content, "reference-domain-probe"));
    REQUIRE(close(fd) == 0);
}

static void claim_busy(void)
{
    errno = 0;
    int fd = open(device, O_RDONLY | O_EXCL | O_CLOEXEC);
    int error = errno;
    if (fd >= 0)
        close(fd);
    REQUIRE(fd == -1 && error == EBUSY);
}

static void mount_busy(void)
{
    errno = 0;
    int result = umount2(base, 0);
    int error = errno;
    REQUIRE(result == -1 && error == EBUSY);
    preserved();
    claim_busy();
}

/* Challenge the proposed exclusive boundary, then remount and verify that no
 * metadata was destroyed. This is not physical-absence or durable-release proof. */
static void release_and_retry(void)
{
    REQUIRE(umount2(base, 0) == 0);
    int claim = open(device, O_RDONLY | O_EXCL | O_CLOEXEC);
    REQUIRE(claim >= 0);
    errno = 0;
    int result = mount(device, alias, "ext4", MS_NODEV | MS_NOSUID, "");
    int error = errno;
    REQUIRE(result == -1 && error == EBUSY);
    REQUIRE(close(claim) == 0);
    mount_base();
    preserved();
    REQUIRE(umount2(base, 0) == 0);
}

static void receipt(const char *name, int path_gap)
{
    cases++;
    printf("{\"case\":\"%s\",\"componentAssertionsPassed\":true,"
           "\"releaseRetryClaimed\":true,\"remountWhileClaimedErrno\":%d,"
           "\"originalPathGapObserved\":%s,\"fullContractSatisfied\":false,"
           "\"productionQualified\":false}\n", name, EBUSY,
           path_gap ? "true" : "false");
    fflush(stdout);
}

static void late_opath(void)
{
    mount_base();
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (!child) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            _exit(120);
        raise(SIGSTOP);
        int result = umount2(base, 0), error = errno;
        _exit(result == -1 && error == EBUSY ? 0 : 121);
    }
    int status;
    REQUIRE(waitpid(child, &status, 0) == child && WIFSTOPPED(status));
    if (ptrace(PTRACE_SETOPTIONS, child, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        REQUIRE(0);
    }
    int held = -1, attempted = 0, observed = 0, child_exit = -1;
    long long syscall_result = 0;
    REQUIRE(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0);
    for (;;) {
        REQUIRE(waitpid(child, &status, 0) == child);
        if (WIFEXITED(status)) {
            child_exit = WEXITSTATUS(status);
            break;
        }
        REQUIRE(WIFSTOPPED(status));
        int sig = WSTOPSIG(status), deliver = 0;
        if (sig == (SIGTRAP | 0x80)) {
            struct __ptrace_syscall_info info = {0};
            REQUIRE(ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info) >= 0);
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY &&
                info.entry.nr == SYS_umount2 && !attempted) {
                REQUIRE(info.entry.args[1] == 0);
                attempted = 1;
                held = open(target, O_PATH | O_CLOEXEC);
                REQUIRE(held >= 0);
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && attempted && !observed) {
                observed = 1;
                syscall_result = (long long)info.exit.rval;
                REQUIRE(info.exit.is_error);
            }
        } else if (sig != SIGSTOP) {
            deliver = sig;
        }
        REQUIRE(ptrace(PTRACE_SYSCALL, child, 0, deliver) == 0);
    }
    REQUIRE(attempted && observed && syscall_result == -EBUSY && child_exit == 0);
    struct stat held_stat;
    REQUIRE(fstat(held, &held_stat) == 0 && same(&original, &held_stat));
    REQUIRE(held_stat.st_nlink == 1);
    preserved();
    claim_busy();
    printf("{\"observation\":\"late-opath-at-umount2-entry\","
           "\"attempted\":true,\"opened\":true,\"umountFlags\":0,"
           "\"syscallResult\":%lld,\"sameHeldInode\":true,"
           "\"originalPathPreserved\":true,\"linkCount\":%llu,"
           "\"childExitCode\":%d,\"productionQualified\":false}\n",
           syscall_result, (unsigned long long)held_stat.st_nlink, child_exit);
    REQUIRE(close(held) == 0);
    release_and_retry();
    receipt("late-opath", 0);
}

static void queued_descriptor(void)
{
    mount_base();
    int sockets[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets) == 0);
    int held = open(target, O_PATH | O_CLOEXEC);
    REQUIRE(held >= 0);
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    char byte = 'R';
    struct iovec data = {.iov_base = &byte, .iov_len = 1};
    struct msghdr message = {.msg_iov = &data, .msg_iovlen = 1,
                            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &held, sizeof(held));
    REQUIRE(sendmsg(sockets[0], &message, 0) == 1);
    REQUIRE(close(held) == 0);
    mount_busy(); /* Only the socket queue now holds the sent O_PATH file. */
    REQUIRE(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    release_and_retry();
    receipt("queued-scm-rights", 0);
}

static void alias_rejection(int detached)
{
    mount_base();
    int held = -1, ready[2] = {-1, -1};
    pid_t worker = -1;
    if (detached) {
        REQUIRE(mount(base, alias, NULL, MS_BIND, NULL) == 0);
        held = open(alias_target, O_PATH | O_CLOEXEC);
        REQUIRE(held >= 0);
        /* Adversarial fixture construction only, never retirement evidence. */
        REQUIRE(umount2(alias, MNT_DETACH) == 0);
    } else {
        REQUIRE(pipe2(ready, O_CLOEXEC) == 0);
        pid_t parent = getpid();
        worker = fork();
        REQUIRE(worker >= 0);
        if (!worker) {
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
                _exit(122);
            close(ready[0]);
            if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
                mount(base, alias, NULL, MS_BIND, NULL) || umount2(base, 0))
                _exit(123);
            held = open(alias_target, O_PATH | O_CLOEXEC);
            if (held < 0 || write(ready[1], "R", 1) != 1)
                _exit(124);
            close(ready[1]);
            for (;;)
                pause();
        }
        REQUIRE(close(ready[1]) == 0);
        char byte = 0;
        REQUIRE(read(ready[0], &byte, 1) == 1 && byte == 'R');
        REQUIRE(close(ready[0]) == 0);
    }
    REQUIRE(umount2(base, 0) == 0);
    claim_busy(); /* An alias survives outside the original visible mount. */
    struct stat missing;
    errno = 0;
    REQUIRE(lstat(target, &missing) == -1 && errno == ENOENT);
    mount_base();
    preserved(); /* Recovery is not proof of continuous path preservation. */
    if (detached) {
        REQUIRE(close(held) == 0);
    } else {
        REQUIRE(kill(worker, SIGKILL) == 0);
        int status;
        REQUIRE(waitpid(worker, &status, 0) == worker && WIFSIGNALED(status));
    }
    release_and_retry();
    receipt(detached ? "detached-alias" : "independent-namespace-alias", 1);
}

int main(int argc, char **argv)
{
    REQUIRE(argc == 4 && geteuid() == 0);
    REQUIRE(getenv("RUNNERD09_REFERENCE_DOMAIN_PROTOTYPE") &&
            !strcmp(getenv("RUNNERD09_REFERENCE_DOMAIN_PROTOTYPE"), "1"));
    REQUIRE(access("/etc/neticora-runnerd-lab", F_OK) == 0);
    device = argv[1];
    struct stat directory, backing, block;
    REQUIRE(lstat(argv[2], &directory) == 0 && S_ISDIR(directory.st_mode) &&
            directory.st_uid == 0 && !(directory.st_mode & 0077));
    REQUIRE(lstat(argv[3], &backing) == 0 && S_ISREG(backing.st_mode) && backing.st_uid == 0);
    int loop = open(device, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct loop_info64 info = {0};
    REQUIRE(loop >= 0 && fstat(loop, &block) == 0 && S_ISBLK(block.st_mode));
    REQUIRE(ioctl(loop, LOOP_GET_STATUS64, &info) == 0 &&
            info.lo_device == (unsigned long long)backing.st_dev && info.lo_inode == backing.st_ino);
    REQUIRE(close(loop) == 0);
    join(base, argv[2], "mount");
    join(alias, argv[2], "alias");
    join(target, base, "protected");
    join(alias_target, alias, "protected");
    REQUIRE(mkdir(base, 0700) == 0 && mkdir(alias, 0700) == 0);
    mount_base();
    int file = open(target, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    REQUIRE(file >= 0 && ftruncate(file, 4096) == 0);
    REQUIRE(write(file, "reference-domain-probe", 22) == 22);
    REQUIRE(fsync(file) == 0 && fstat(file, &original) == 0 && close(file) == 0);
    preserved();
    claim_busy();
    release_and_retry();
    receipt("no-reference-control", 0);
    late_opath();
    mount_base();
    file = open(target, O_RDONLY | O_CLOEXEC);
    REQUIRE(file >= 0);
    void *mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, file, 0);
    REQUIRE(mapping != MAP_FAILED && close(file) == 0);
    mount_busy();
    REQUIRE(munmap(mapping, 4096) == 0);
    release_and_retry();
    receipt("closed-fd-mapping", 0);
    mount_base();
    int dirfd = open(base, O_PATH | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(dirfd >= 0);
    mount_busy();
    REQUIRE(close(dirfd) == 0);
    release_and_retry();
    receipt("retained-directory", 0);
    queued_descriptor();
    alias_rejection(0);
    alias_rejection(1);
    REQUIRE(cases == 7);
    printf("{\"scope\":\"dedicated-filesystem-kernel-component-prototype\","
           "\"cases\":%u,\"componentAssertionsPassed\":true,"
           "\"originalPathGapCases\":2,\"fullContractSatisfied\":false,"
           "\"productionQualified\":false,\"physicalAbsenceProved\":false}\n", cases);
    return 0;
}
