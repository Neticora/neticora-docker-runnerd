#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
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
    struct iovec plain={.iov_base="plain-byte-stream",.iov_len=17};
    struct msghdr plainmsg={.msg_iov=&plain,.msg_iovlen=1};
    if(sendmsg(socket,&plainmsg,0)!=17) exit(26);
    close(fd);close(socket);
}
static int pass_fd(int socket,int fd) {
    char control[CMSG_SPACE(sizeof(int))]={0},byte='x';
    struct iovec data={.iov_base=&byte,.iov_len=1};
    struct msghdr message={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&message);
    c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&fd,sizeof(fd));return sendmsg(socket,&message,0);
}
static int atomic_report(const char *path,const char *value) {
    char temporary[4096];
    if(snprintf(temporary,sizeof(temporary),"%s.pending",path)>=(int)sizeof(temporary))return -1;
    FILE *out=fopen(temporary,"wx");if(!out)return -1;
    if(fputs(value,out)==EOF||fflush(out)||fsync(fileno(out))||fclose(out)||rename(temporary,path))return -1;
    return 0;
}
struct thread_args {int socket,fd,result;};
static void *thread_transfer(void *opaque) {
    struct thread_args *a=opaque;
    /* Deliberately diverge from the group leader's descriptor table. A
     * mediator using a tgid instead of the notifying tid cannot pass this. */
    if(unshare(CLONE_FILES)||dup2(a->fd,199)!=199){a->result=41;return NULL;}
    a->result=pass_fd(a->socket,199)==1?0:42;
    close(199);return NULL;
}
static int internal_transfer(const char *target) {
    int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair))return 43;
    int fd=open(target,O_PATH|O_CLOEXEC);if(fd<0)return 44;
    int event=eventfd(0,EFD_CLOEXEC);if(event<0)return 45;
    /* Positive controls ensure outward denial did not merely disable the
     * mediator, ptrace permission, PIDFD_THREAD or every descriptor transfer. */
    struct thread_args args={.socket=pair[0],.fd=fd,.result=46};pthread_t thread;
    if(pthread_create(&thread,NULL,thread_transfer,&args)||pthread_join(thread,NULL)||args.result)return 46;
    char byte=0,control[128]={0};struct iovec data={.iov_base=&byte,.iov_len=1};
    struct msghdr message={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    if(recvmsg(pair[1],&message,MSG_CMSG_CLOEXEC)!=1)return 47;
    struct cmsghdr *c=CMSG_FIRSTHDR(&message);int received=-1;
    if(!c||c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS||c->cmsg_len!=CMSG_LEN(sizeof(int)))return 48;
    memcpy(&received,CMSG_DATA(c),sizeof(received));
    struct stat a,b;if(fstat(fd,&a)||fstat(received,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino)return 49;
    close(received);
    if(pass_fd(pair[0],event)!=1)return 50;
    memset(control,0,sizeof(control));message.msg_controllen=sizeof(control);
    if(recvmsg(pair[1],&message,MSG_CMSG_CLOEXEC)!=1)return 51;
    c=CMSG_FIRSTHDR(&message);if(!c||c->cmsg_len!=CMSG_LEN(sizeof(int)))return 52;
    memcpy(&received,CMSG_DATA(c),sizeof(received));close(received);
    errno=0;if(pass_fd(pair[0],pair[1])!=-1||errno!=EPERM)return 53;
    int ns=open("/proc/self/ns/pid",O_RDONLY|O_CLOEXEC);if(ns<0)return 54;
    errno=0;if(pass_fd(pair[0],ns)!=-1||errno!=EPERM)return 55;
    if(dup2(pair[0],198)!=198)return 56;
    errno=0;if(pass_fd(198,fd)!=-1||errno!=EPERM)return 57;
    struct sock_filter instructions[]={BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF)};
    struct sock_fprog program={.len=1,.filter=instructions};
    errno=0;if(syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&program)!=-1||errno!=EPERM)return 58;
    close(ns);close(198);close(event);close(fd);close(pair[0]);close(pair[1]);
    printf("INTERNAL_THREAD_FD_EVENTFD_TRANSFER_VERIFIED_SOCKET_NAMESPACE_RELAY_DENIED\n");return 0;
}
struct race_args {int inside,outside,receive,fd;atomic_int stop;atomic_int error;};
static void *replace_socket(void *opaque) {
    struct race_args *a=opaque;
    while(!atomic_load(&a->stop)) {
        if(dup2(a->inside,200)!=200||dup2(a->outside,200)!=200)atomic_store(&a->error,59);
    }
    return NULL;
}
static void *receive_internal(void *opaque) {
    struct race_args *a=opaque;
    for(;;) {
        char byte,control[128]={0};struct iovec data={.iov_base=&byte,.iov_len=1};
        struct msghdr message={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        ssize_t n=recvmsg(a->receive,&message,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
        if(n<0&&errno==EAGAIN) {if(atomic_load(&a->stop))break;sched_yield();continue;}
        if(n!=1||message.msg_flags&(MSG_CTRUNC|MSG_TRUNC)){atomic_store(&a->error,60);break;}
        struct cmsghdr *c=CMSG_FIRSTHDR(&message);int received=-1;
        if(!c||c->cmsg_len!=CMSG_LEN(sizeof(int))||c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS) {
            atomic_store(&a->error,61);break;
        }
        memcpy(&received,CMSG_DATA(c),sizeof(received));
        struct stat expected,actual;
        if(fstat(a->fd,&expected)||fstat(received,&actual)||expected.st_dev!=actual.st_dev||expected.st_ino!=actual.st_ino)
            atomic_store(&a->error,62);
        close(received);
    }
    return NULL;
}
static int race_transfer(const char *outside,const char *target) {
    int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair))return 63;
    int fd=open(target,O_PATH|O_CLOEXEC);if(fd<0)return 64;
    struct race_args a={.inside=pair[0],.outside=connect_to(outside),.receive=pair[1],.fd=fd};
    if(dup2(a.inside,200)!=200)return 65;
    pthread_t change,receive;
    if(pthread_create(&change,NULL,replace_socket,&a)||pthread_create(&receive,NULL,receive_internal,&a))return 66;
    int accepted=0,denied=0;
    for(int i=0;i<2000;i++) {
        int n=pass_fd(200,fd);
        if(n==1)accepted++;
        else if(n<0&&errno==EPERM)denied++;
        if(n!=1&&!(n<0&&(errno==EPERM||errno==EAGAIN))) {atomic_store(&a.error,67);break;}
    }
    atomic_store(&a.stop,1);
    if(pthread_join(change,NULL)||pthread_join(receive,NULL))return 68;
    /* External receiver must see this terminal byte packet and no rights. */
    if(write(a.outside,"plain-byte-stream",17)!=17)return 69;
    close(200);close(fd);close(a.outside);close(pair[0]);close(pair[1]);
    if(atomic_load(&a.error))return atomic_load(&a.error);
    if(!accepted||!denied)return 70;
    printf("CONCURRENT_SOCKET_REPLACEMENT_2000_ATTEMPTS internal=%d outside_denied=%d NO_OUTWARD_RIGHTS\n",accepted,denied);return 0;
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
        uid_t real,effective,saved;
        if(getresuid(&real,&effective,&saved)||real||effective||saved)return 71;
        errno=0;if(setuid(10003)!=-1||errno!=EPERM)return 72;
        errno=0;if(setreuid(10003,10003)!=-1||errno!=EPERM)return 73;
        errno=0;if(setresuid(10003,10003,10003)!=-1||errno!=EPERM)return 74;
        errno=0;if(prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0)!=-1||errno!=EPERM)return 75;
        errno=0;if(unshare(CLONE_NEWUSER)!=-1||errno!=EPERM)return 76;
        pid_t next=syscall(SYS_clone,CLONE_NEWUSER|SIGCHLD,NULL,NULL,NULL,0);
        if(!next)_exit(77);
        if(next!=-1||errno!=EPERM)return 77;
        printf("UID_TRIPLET_SEALED_AFTER_EXEC dumpable=%d\n",prctl(PR_GET_DUMPABLE,0,0,0,0));
        printf("PRIVILEGE_AND_FILTER_SEAL_VERIFIED\n");return 0;
    }
    if(!strcmp(argv[1],"guardian-loss")) {
        if(argc!=5)return 2;
        pid_t guardian=getppid(),child=fork();if(child<0)return 78;
        if(child)return 0;
        char value[128];snprintf(value,sizeof(value),"%ld %ld\n",(long)getpid(),(long)guardian);
        if(atomic_report(argv[4],value))_exit(79);
        char trigger[4096],done[4096];
        if(snprintf(trigger,sizeof(trigger),"%s.trigger",argv[4])>=(int)sizeof(trigger)||
           snprintf(done,sizeof(done),"%s.done",argv[4])>=(int)sizeof(done))_exit(80);
        int i;for(i=0;i<10000&&access(trigger,F_OK);i++)usleep(1000);
        if(i==10000)_exit(81);
        int socket=connect_to(argv[2]),fd=open(argv[3],O_PATH|O_CLOEXEC);
        if(fd<0)_exit(82);
        errno=0;if(pass_fd(socket,fd)!=-1||errno!=ENOSYS)_exit(83);
        if(write(socket,"plain-byte-stream",17)!=17)_exit(84);
        if(atomic_report(done,"GUARDIAN_LOSS_ENOSYS_NO_OUTWARD_RIGHTS\n"))_exit(85);
        close(fd);close(socket);_exit(0);
    }
    if(!strcmp(argv[1],"confinement")) {
        if(argc!=8)return 2;
        char label[256]={0};int current=open("/proc/self/attr/current",O_RDONLY|O_CLOEXEC);
        if(current<0||read(current,label,sizeof(label)-1)<1)return 86;
        close(current);
        char expected[256];snprintf(expected,sizeof(expected),"%s (enforce)",argv[6]);
        if(strncmp(label,expected,strlen(expected)))return 87;
        errno=0;int fd=open(argv[2],O_RDONLY|O_CLOEXEC);
        if(fd!=-1||errno!=EACCES)return 88;
        errno=0;fd=open(argv[2],O_WRONLY|O_TRUNC|O_CLOEXEC);
        if(fd!=-1||errno!=EACCES)return 89;
        errno=0;if(unlink(argv[2])!=-1||errno!=EACCES)return 90;
        errno=0;if(chmod(argv[3],0777)!=-1||errno!=EACCES)return 91;
        errno=0;if(chmod(argv[4],0777)!=-1||errno!=EACCES)return 92;
        errno=0;if(chown(argv[3],10003,10003)!=-1||errno!=EACCES)return 106;
        errno=0;if(chown(argv[4],10003,10003)!=-1||errno!=EACCES)return 107;
        char alias[4096];snprintf(alias,sizeof(alias),"%s/state-alias",argv[4]);
        errno=0;if(link(argv[2],alias)!=-1||errno!=EACCES)return 108;
        if(symlink(argv[2],alias))return 109;
        errno=0;fd=open(alias,O_RDONLY|O_CLOEXEC);
        if(fd!=-1||errno!=EACCES)return 110;
        if(unlink(alias))return 111;
        char positive[4096];snprintf(positive,sizeof(positive),"%s/scratch/owned",argv[3]);
        fd=open(positive,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(fd<0||write(fd,"owned",5)!=5)return 93;
        close(fd);
        int sock=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
        struct sockaddr_un address={.sun_family=AF_UNIX};
        if(sock<0||strlen(argv[5])>=sizeof(address.sun_path))return 94;
        memcpy(address.sun_path,argv[5],strlen(argv[5])+1);
        errno=0;if(connect(sock,(struct sockaddr *)&address,sizeof(address))!=-1||errno!=EACCES)return 95;
        close(sock);
        sock=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
        if(sock<0||argv[7][0]!='@'||strlen(argv[7])>=sizeof(address.sun_path))return 101;
        memset(address.sun_path,0,sizeof(address.sun_path));
        memcpy(address.sun_path+1,argv[7]+1,strlen(argv[7])-1);
        errno=0;if(connect(sock,(struct sockaddr *)&address,
            offsetof(struct sockaddr_un,sun_path)+strlen(argv[7]))!=-1||errno!=EACCES)return 102;
        close(sock);
        char protected[4096];snprintf(protected,sizeof(protected),"%s/apparmor",argv[3]);
        errno=0;fd=open(protected,O_WRONLY|O_TRUNC|O_CLOEXEC);
        if(fd!=-1||errno!=EACCES)return 103;
        snprintf(protected,sizeof(protected),"%s/d.sock",argv[3]);
        sock=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
        if(sock<0||strlen(protected)>=sizeof(address.sun_path))return 104;
        memset(address.sun_path,0,sizeof(address.sun_path));
        memcpy(address.sun_path,protected,strlen(protected)+1);
        errno=0;if(connect(sock,(struct sockaddr *)&address,sizeof(address))!=-1||errno!=EACCES)return 105;
        close(sock);
        pid_t child=fork();if(child<0)return 96;
        if(!child) {execl("/usr/bin/true","true",NULL);_exit(errno==EACCES?97:98);}
        int status;while(waitpid(child,&status,0)<0)if(errno!=EINTR)return 99;
        if(!WIFEXITED(status)||WEXITSTATUS(status)!=97)return 100;
        printf("CONFINEMENT_ENFORCED_STATE_ALIAS_POLICY_WRITE_GUARD_CHMOD_CHOWN_DOCKER_ABSTRACT_SUPERVISOR_SOCKET_UNAPPROVED_EXEC_DENIED\n");
        return 0;
    }
    if(!strcmp(argv[1],"control-socket")) {
        int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
        struct sockaddr_un address={.sun_family=AF_UNIX};
        if(fd<0||strlen(argv[2])>=sizeof(address.sun_path))return 114;
        memcpy(address.sun_path,argv[2],strlen(argv[2])+1);
        errno=0;
        if(connect(fd,(struct sockaddr *)&address,sizeof(address))!=-1||errno!=EACCES)return 115;
        close(fd);printf("PRIVILEGED_CONTAINERD_SOCKET_CONNECT_DENIED %s\n",argv[2]);return 0;
    }
    if(!strcmp(argv[1],"transfer")) {
        if(argc!=4)return 2;
        denied_transfer(argv[2],argv[3]);
        printf("FD_TRANSFER_DENIED\n");return 0;
    }
    if(!strcmp(argv[1],"internal-transfer"))return internal_transfer(argv[2]);
    if(!strcmp(argv[1],"race-transfer")) {
        if(argc!=4)return 2;
        return race_transfer(argv[2],argv[3]);
    }
    if(!strcmp(argv[1],"escape")) {
        int fd=open(argv[2],O_RDONLY|O_CLOEXEC);if(fd<0)return 3;
        errno=0;if(setns(fd,CLONE_NEWPID)!=-1 || errno!=EPERM)return 4;
        errno=0;if(setns(fd,0)!=-1 || errno!=EPERM)return 5;
        errno=0;if(setns(fd,CLONE_NEWUSER)!=-1 || errno!=EPERM)return 5;
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
    if(!strcmp(argv[1],"hold")||!strcmp(argv[1],"acquire-loop")||!strcmp(argv[1],"reply-loss")) {
        if(argc!=4)return 2;
        pid_t child=fork();if(child<0)return 9;
        if(child) {
            if(!strcmp(argv[1],"reply-loss")) {
                char trigger[4096];
                if(snprintf(trigger,sizeof(trigger),"%s.trigger",argv[3])>=(int)sizeof(trigger))return 112;
                int i;for(i=0;i<10000&&access(trigger,F_OK);i++)usleep(1000);
                if(i==10000)return 113;
            }
            return 0;
        }
        int fd=open(argv[2],O_PATH|O_DIRECTORY|O_CLOEXEC);if(fd<0)_exit(10);
        char temporary[4096];
        if(snprintf(temporary,sizeof(temporary),"%s.pending",argv[3])>=(int)sizeof(temporary))_exit(11);
        FILE *report=fopen(temporary,"wx");if(!report)_exit(11);
        struct stat s;if(fstat(fd,&s))_exit(12);
        fprintf(report,"%ld %lu %lu\n",(long)getpid(),(unsigned long)s.st_dev,(unsigned long)s.st_ino);
        if(fflush(report)||fsync(fileno(report))||fclose(report)||rename(temporary,argv[3]))_exit(13);
        if(!strcmp(argv[1],"acquire-loop")) {
            for(;;) {
                pid_t next=fork();if(next<0)_exit(14);
                if(!next) {
                    int acquired=open(argv[2],O_PATH|O_DIRECTORY|O_CLOEXEC);
                    if(acquired<0)_exit(15);
                    usleep(20000);close(acquired);_exit(0);
                }
                int status;
                while(waitpid(next,&status,0)<0)if(errno!=EINTR)_exit(16);
                if(!WIFEXITED(status)||WEXITSTATUS(status))_exit(17);
            }
        }
        for(;;)pause();
    }
    return 2;
}
