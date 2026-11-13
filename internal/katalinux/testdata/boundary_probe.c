#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Adversarial native fixture; no original Docker/VM allocation is involved. */
static int connect_to(const char *path) {
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    struct sockaddr_un a={.sun_family=AF_UNIX};
    if (fd<0 || strlen(path)>=sizeof(a.sun_path)) exit(20);
    memcpy(a.sun_path,path,strlen(path)+1);
    if (connect(fd,(struct sockaddr *)&a,sizeof(a))) exit(21);
    return fd;
}
static void denied_transfer(const char *path,const char *target) {
    int socket=connect_to(path),fd=open(target,O_PATH|O_CLOEXEC);
    if (fd<0) exit(22);
    char control[CMSG_SPACE(sizeof(int))]={0},byte='x';
    struct iovec data={.iov_base=&byte,.iov_len=1};
    struct msghdr msg={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    struct cmsghdr *header=CMSG_FIRSTHDR(&msg);
    header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;header->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header),&fd,sizeof(fd));
    errno=0;if(sendmsg(socket,&msg,0)!=-1 || errno!=EPERM) exit(23);
    struct mmsghdr multi={.msg_hdr=msg};
    errno=0;if(sendmmsg(socket,&multi,1,0)!=-1 || errno!=EPERM) exit(24);
    errno=0;if(syscall(SYS_io_uring_setup,1,NULL)!=-1 || errno!=EPERM) exit(25);
    /* Plain bytes cannot carry SCM_RIGHTS and must remain usable. */
    if(write(socket,"plain-byte-stream",17)!=17) exit(26);
    close(fd);close(socket);
}
int main(int argc,char **argv){
    if(argc<3)return 2;
    if(!strcmp(argv[1],"privileges")) {
        struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
        struct __user_cap_data_struct caps[2];
        if(syscall(SYS_capget,&header,caps))return 30;
        const int denied[]={CAP_SYS_MODULE,CAP_SYS_RAWIO,CAP_SYS_PTRACE,CAP_SYS_BOOT,
            CAP_MAC_ADMIN,CAP_MAC_OVERRIDE,CAP_SYSLOG,CAP_SETPCAP,CAP_BPF,CAP_PERFMON,
            CAP_CHECKPOINT_RESTORE,CAP_AUDIT_CONTROL,CAP_AUDIT_WRITE,CAP_AUDIT_READ};
        for(size_t i=0;i<sizeof(denied)/sizeof(denied[0]);i++) {
            unsigned index=(unsigned)denied[i]/32,mask=1U<<((unsigned)denied[i]%32);
            if((caps[index].permitted|caps[index].effective|caps[index].inheritable)&mask)return 31;
            if(prctl(PR_CAPBSET_READ,denied[i])!=0)return 32;
        }
        if(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2)return 33;
        errno=0;if(syscall(SYS_finit_module,-1,"",0)!=-1||errno!=EPERM)return 34;
        errno=0;if(syscall(SYS_io_uring_enter,-1,0,0,0,NULL,0)!=-1||errno!=EPERM)return 35;
        printf("PRIVILEGE_AND_FILTER_SEAL_VERIFIED\n");return 0;
    }
    if(!strcmp(argv[1],"transfer")) {
        if(argc!=4)return 2;
        denied_transfer(argv[2],argv[3]);
        printf("FD_TRANSFER_DENIED\n");return 0;
    }
    if(!strcmp(argv[1],"escape")) {
        int fd=open(argv[2],O_RDONLY|O_CLOEXEC);if(fd<0)return 3;
        errno=0;if(setns(fd,CLONE_NEWPID)!=-1 || errno!=EPERM)return 4;
        errno=0;if(setns(fd,0)!=-1 || errno!=EPERM)return 5;
        errno=0;if(prctl(PR_SET_DUMPABLE,1)!=-1 || errno!=EPERM)return 6;
        close(fd);printf("PID_NAMESPACE_ESCAPE_DENIED\n");return 0;
    }
    if(!strcmp(argv[1],"keeper-control")) {
        signal(SIGPIPE,SIG_IGN);
        int fd=connect_to(argv[2]);
        ssize_t n=write(fd,"STOP\0",5);
        if(n<0 && errno!=EPIPE && errno!=ECONNRESET)return 7;
        if(n==5) {
            int32_t reply=0;n=read(fd,&reply,sizeof(reply));
            if(!((n==(ssize_t)sizeof(reply)&&reply==125)||n==0||
                 (n<0&&(errno==ECONNRESET||errno==EPIPE))))return 8;
        } else if(n>=0)return 7;
        close(fd);printf("INNER_ROOT_CONTROL_DENIED\n");return 0;
    }
    if(!strcmp(argv[1],"hold")) {
        if(argc!=4)return 2;
        pid_t child=fork();if(child<0)return 9;
        if(child)return 0;
        int fd=open(argv[2],O_PATH|O_DIRECTORY|O_CLOEXEC);if(fd<0)_exit(10);
        char temporary[4096];
        if(snprintf(temporary,sizeof(temporary),"%s.pending",argv[3])>=(int)sizeof(temporary))_exit(11);
        FILE *report=fopen(temporary,"wx");if(!report)_exit(11);
        struct stat s;if(fstat(fd,&s))_exit(12);
        fprintf(report,"%ld %lu %lu\n",(long)getpid(),(unsigned long)s.st_dev,(unsigned long)s.st_ino);
        if(fflush(report)||fsync(fileno(report))||fclose(report)||rename(temporary,argv[3]))_exit(13);
        for(;;)pause();
    }
    return 2;
}
