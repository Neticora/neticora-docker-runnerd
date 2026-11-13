#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Qualification only. Both processes inherit the original execution cgroup.
 * The child retains a directory after the opener exits; fd-pass receives its
 * only handle over SCM_RIGHTS after closing the inherited original descriptor.
 * This does not qualify transfers to a receiver outside the owned domain. */
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int transfer = !strcmp(argv[1], "fd-pass");
    if (!transfer && strcmp(argv[1], "fork-dir")) return 2;
    int fd = open(argv[2], O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return 3;
    struct stat original;
    if (fstat(fd, &original)) return 4;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets)) return 5;
    pid_t opener = getpid();
    pid_t child = fork();
    if (child < 0) return 6;
    if (child) {
        close(sockets[1]);
        if (transfer) {
            char control[CMSG_SPACE(sizeof(int))] = {0}, payload = 'f';
            struct iovec data = {.iov_base = &payload, .iov_len = 1};
            struct msghdr msg = {.msg_iov = &data, .msg_iovlen = 1,
                .msg_control = control, .msg_controllen = sizeof(control)};
            struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(header), &fd, sizeof(fd));
            if (sendmsg(sockets[0], &msg, 0) != 1) return 7;
        }
        close(fd);
        close(sockets[0]);
        return 0;
    }
    close(sockets[0]);
    if (transfer) {
        close(fd);
        char control[CMSG_SPACE(sizeof(int))] = {0}, payload;
        struct iovec data = {.iov_base = &payload, .iov_len = 1};
        struct msghdr msg = {.msg_iov = &data, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control)};
        if (recvmsg(sockets[1], &msg, MSG_CMSG_CLOEXEC) != 1 ||
            msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) return 8;
        struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
        if (!header || CMSG_NXTHDR(&msg, header) ||
            header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len != CMSG_LEN(sizeof(int))) return 9;
        memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    }
    close(sockets[1]);
    struct stat retained;
    if (fstat(fd, &retained) || retained.st_dev != original.st_dev ||
        retained.st_ino != original.st_ino) return 10;
    for (int i = 0; getppid() == opener; i++) {
        if (i == 500) return 11;
        usleep(10000);
    }
    printf("READY %ld\n", (long)getpid());
    fflush(stdout);
    for (;;) pause();
}
