#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

/* Trace only a freshly spawned test child. No attachment to existing tasks,
 * writes to tracee memory, syscall substitution, or production guard bypass.
 * PTRACE_O_EXITKILL terminates the tracees if the bounded caller kills us. */
static int peek_string(pid_t tid, uintptr_t address, char *out, size_t size)
{
    for (size_t i = 0; i < size; i += sizeof(long)) {
        errno = 0;
        long value = ptrace(PTRACE_PEEKDATA, tid, (void *)(address + i), 0);
        if (errno)
            return -1;
        size_t count = size - i < sizeof(long) ? size - i : sizeof(long);
        memcpy(out + i, &value, count);
        if (memchr(out + i, 0, count))
            return 0;
    }
    return -1;
}

static int is_target(pid_t tid, const struct __ptrace_syscall_info *info,
                     const char *target)
{
    char name[PATH_MAX], base[PATH_MAX], joined[PATH_MAX], resolved[PATH_MAX];
    char link[128];
    if (peek_string(tid, (uintptr_t)info->entry.args[1], name, sizeof(name)))
        return 0;
    if (name[0] == '/') {
        memcpy(joined, name, strlen(name) + 1);
    } else {
        int fd = (int)info->entry.args[0];
        if (fd == AT_FDCWD)
            snprintf(link, sizeof(link), "/proc/%ld/cwd", (long)tid);
        else
            snprintf(link, sizeof(link), "/proc/%ld/fd/%d", (long)tid, fd);
        ssize_t count = readlink(link, base, sizeof(base) - 1);
        if (count < 0)
            return 0;
        base[count] = 0;
        size_t parent = (size_t)count, leaf = strlen(name);
        if (parent + leaf + 2 > sizeof(joined))
            return 0;
        memcpy(joined, base, parent);
        joined[parent] = '/';
        memcpy(joined + parent + 1, name, leaf + 1);
    }
    return realpath(joined, resolved) && !strcmp(resolved, target);
}

static int same_inode(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: probe TEST_BINARY FIXTURE TARGET\n");
        return 2;
    }
    /* Establish initial access, identity and a canonical path before the child
     * starts. Close this descriptor before any absence scan. */
    char target[PATH_MAX];
    struct stat original;
    if (!realpath(argv[3], target))
        return 2;
    int initial = open(target, O_PATH | O_CLOEXEC);
    if (initial < 0 || fstat(initial, &original))
        return 2;
    close(initial);
    if (setenv("RUNNERD09_SANDBOX_CHILD_FIXTURE", argv[2], 1) ||
        setenv("RUNNERD09_SANDBOX_CHILD_PHASE", "complete", 1))
        return 2;
    pid_t child = fork();
    if (child < 0)
        return 2;
    if (!child) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            _exit(123);
        raise(SIGSTOP);
        execl(argv[1], argv[1], "-test.v",
              "-test.run=^TestSandboxCleanupProcessChild$",
              "-test.timeout=70s", NULL);
        _exit(124);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status))
        return 2;
    if (ptrace(PTRACE_SETOPTIONS, child, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL) < 0 ||
        ptrace(PTRACE_SYSCALL, child, 0, 0) < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 2;
    }
    int held = -1, exit_code = -1, attempted = 0, open_errno = 0;
    int trace_error = 0;
    pid_t unlink_tid = 0;
    int unlink_observed = 0, unlink_error = 0;
    long long unlink_result = -1;
    struct stat acquired = {0};
    for (;;) {
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid < 0) {
            if (errno == EINTR)
                continue;
            if (errno != ECHILD)
                trace_error = 1;
            break;
        }
        if (WIFEXITED(status)) {
            if (tid == child)
                exit_code = WEXITSTATUS(status);
            continue;
        }
        if (WIFSIGNALED(status)) {
            if (tid == child)
                exit_code = 128 + WTERMSIG(status);
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;
        int sig = WSTOPSIG(status), event = (unsigned)status >> 16;
        int deliver = 0;
        if (sig == (SIGTRAP | 0x80)) {
            struct __ptrace_syscall_info info = {0};
            if (ptrace(PTRACE_GET_SYSCALL_INFO, tid, sizeof(info), &info) < 0) {
                trace_error = 1;
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT &&
                       tid == unlink_tid && !unlink_observed) {
                unlink_observed = 1;
                unlink_result = (long long)info.exit.rval;
                unlink_error = info.exit.is_error;
            } else if (!attempted && info.op == PTRACE_SYSCALL_INFO_ENTRY &&
                       info.entry.nr == SYS_unlinkat &&
                       is_target(tid, &info, target)) {
                attempted = 1;
                unlink_tid = tid;
                held = open(target, O_PATH | O_CLOEXEC);
                if (held < 0) {
                    open_errno = errno;
                    if (open_errno != EACCES && open_errno != EPERM)
                        trace_error = 1;
                } else if (fstat(held, &acquired) ||
                           !same_inode(&original, &acquired)) {
                    trace_error = 1;
                }
            }
        } else if (sig != SIGSTOP && !(sig == SIGTRAP && event)) {
            deliver = sig;
        }
        if (ptrace(PTRACE_SYSCALL, tid, 0, deliver) < 0 && errno != ESRCH)
            trace_error = 1;
    }
    struct stat after = {0}, path = {0};
    int same_held = held >= 0 && !fstat(held, &after) &&
                    same_inode(&original, &after);
    errno = 0;
    int exists = !lstat(target, &path);
    int absent = !exists && errno == ENOENT;
    int same_path = exists && same_inode(&original, &path);
    int violation = attempted && same_held &&
                    (absent || !same_path || exit_code == 0 ||
                     (unlink_observed && !unlink_error && unlink_result == 0));
    printf("{\"probe\":\"late-opath-unlinkat-v1\","
           "\"attemptedAtUnlink\":%s,\"openedAtUnlink\":%s,"
           "\"openErrno\":%d,\"heldInode\":%llu,\"heldDevice\":%llu,"
           "\"unlinkObserved\":%s,\"unlinkResult\":%lld,\"unlinkError\":%s,"
           "\"heldLinkCountAfter\":%llu,\"sameHeldInodeAfter\":%s,"
           "\"targetAbsent\":%s,\"targetSameInodeAfter\":%s,"
           "\"childExitCode\":%d,\"traceError\":%s,"
           "\"referenceSafetyViolationObserved\":%s}\n",
           attempted ? "true" : "false", held >= 0 ? "true" : "false",
           open_errno, (unsigned long long)original.st_ino,
           (unsigned long long)original.st_dev,
           unlink_observed ? "true" : "false", unlink_result,
           unlink_error ? "true" : "false",
           (unsigned long long)after.st_nlink, same_held ? "true" : "false",
           absent ? "true" : "false", same_path ? "true" : "false", exit_code,
           trace_error ? "true" : "false", violation ? "true" : "false");
    if (held >= 0)
        close(held);
    return trace_error || !attempted || !unlink_observed ? 2 : violation ? 1 : 0;
}
