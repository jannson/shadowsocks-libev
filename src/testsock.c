#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/fcntl.h> // fcntl
#include <unistd.h> // close
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <ev.h>

// TODO
// disconnect and reconnect on each newline

// Nasty globals for now
// feel free to fork this example and clean it up
EV_P;
ev_io stdin_watcher;
ev_io remote_w;
ev_io send_w;
int remote_fd;
char* line = NULL;
size_t len = 0;
char** g_grgv = NULL;

int setCloExec( int fd, int val );

#define HTTP_C_MAGIC        0x10293874
#define HTTP_C_VERSION      0x1
#define HTTP_C_REQ          0x1
#define HTTP_C_RESP         0x2
#define HTTP_C_HAND         0x3
#define HTTP_C_SYNC         0x4
#define HTTP_C_TUNNELREQ    0x5
#define HTTP_C_TUNNELRESP   0x6
#define HTTP_C_HEADER_LEN   sizeof(http_c_header)

typedef struct _http_c_header {
    unsigned int    magic;
    unsigned short  version;
    unsigned short  type;
    unsigned short  length;     /* Length include the header */
    unsigned short  seq;
    unsigned int    reserved;   /* the first byte is use to identify TODO */
}__attribute__ ((packed)) http_c_header;
char* createBuf(int* total_len)
{
    char* pbuf;
    unsigned short len;
    char* str = "hello word";
    http_c_header h, *header;
    header = &h;

    pbuf = (char*)malloc(1024);
    header->magic = htonl(HTTP_C_MAGIC);
    header->version = htons(HTTP_C_VERSION);
    header->type = htons(HTTP_C_REQ);
    len = (unsigned short)(HTTP_C_HEADER_LEN + strlen(str) + 1);
    header->length = htons(len);
    header->seq = htons(0x66);
    header->reserved = 0;
    memcpy(pbuf, header, HTTP_C_HEADER_LEN);
    strcpy(pbuf+HTTP_C_HEADER_LEN, str);

    *total_len = len;

    return pbuf;
}

int recv_cnt = 0;
static void send_cb (EV_P_ ev_io *w, int revents)
{
    if (revents & EV_WRITE)
    {
        puts ("remote ready for writing...");

        line = createBuf((int*)&len);
        if (-1 == send(remote_fd, line, len, 0)) {
            perror("echo send");
            exit(EXIT_FAILURE);
        }
        free(line);
        line = NULL;
        // once the data is sent, stop notifications that
        // data can be sent until there is actually more
        // data to send
        ev_io_stop(EV_A_ &send_w);
        ev_io_set(&send_w, remote_fd, EV_READ);
        ev_io_start(EV_A_ &send_w);
    }
    else if (revents & EV_READ)
    {
        int n;
        char str[100] = ".\0";

        printf("[r,remote]");
        n = recv(remote_fd, str, 100, 0);
        if (n <= 0) {
            if (0 == n) {
                // an orderly disconnect
                puts("orderly disconnect");
                ev_io_stop(EV_A_ &send_w);
                close(remote_fd);
            }  else if (EAGAIN == errno) {
                puts("should never get in this state with libev");
            } else {
                perror("recv");
            }
            return;
        }
        printf("socket client said: %s", str+16);

        recv_cnt++;
        if(recv_cnt > 1) {
            ev_break (EV_A_ EVBREAK_ALL);
        }
    }
}

static void stdin_cb (EV_P_ ev_io *w, int revents)
{
    int len2; // not sure if this is at all useful

    puts ("stdin written to, reading...");
    len2 = getline(&line, &len, stdin);
    ev_io_stop(EV_A_ &send_w);
    ev_io_set (&send_w, remote_fd, EV_READ | EV_WRITE);
    ev_io_start(EV_A_ &send_w);
}

static void remote_cb (EV_P_ ev_io *w, int revents)
{
    puts ("connected, now watching stdin");
    // Once the connection is established, listen to stdin
    //ev_io_start(EV_A_ &stdin_watcher);
    // Once we're connected, that's the end of that

    ev_io_stop(EV_A_ &send_w);
    ev_io_set (&send_w, remote_fd, EV_READ | EV_WRITE);
    ev_io_start(EV_A_ &send_w);

    ev_io_stop(EV_A_ &remote_w);
}


// Simply adds O_NONBLOCK to the file descriptor of choice
int setnonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

int setCloExec( int fd, int val )
{
   unsigned int flags = fcntl( fd, F_GETFD );
   if ( flags == -1 ) return 0;
 
   if ( val )
   {
      if ( fcntl( fd, F_SETFD, flags |  FD_CLOEXEC ) == -1 ) return 0;
   } else {
      if ( fcntl( fd, F_SETFD, flags & ~FD_CLOEXEC ) == -1 ) return 0;
   }
 
   return 1;
}
static void connection_new(EV_P_ char* sock_path) {
    int len;
    struct sockaddr_un remote;

    if (-1 == (remote_fd = socket(AF_UNIX, SOCK_STREAM, 0))) {
        perror("socket");
        exit(1);
    }

    // Set it non-blocking
    if (-1 == setnonblock(remote_fd)) {
        perror("echo client socket nonblock");
        exit(EXIT_FAILURE);
    }

    //setCloExec(remote_fd, 1);

    // this should be initialized before the connect() so
    // that no packets are dropped when initially sent?
    // http://cr.yp.to/docs/connect.html

    // initialize the connect callback so that it starts the stdin asap
    ev_io_init (&remote_w, remote_cb, remote_fd, EV_WRITE);
    ev_io_start(EV_A_ &remote_w);
    // initialize the send callback, but wait to start until there is data to write
    ev_io_init(&send_w, send_cb, remote_fd, EV_READ);
    ev_io_start(EV_A_ &send_w);

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, sock_path);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);

    if (-1 == connect(remote_fd, (struct sockaddr *)&remote, len)) {
        perror("connect");
        exit(1);
    }
}

int acquireLock (char *fileSpec) {
    int lockFd;

    if ((lockFd = open (fileSpec, O_CREAT | O_RDWR, 0666))  < 0)
        return -1;

    if (flock (lockFd, LOCK_EX | LOCK_NB) < 0) {
        close (lockFd);
        return -1;
    }

    return lockFd;
}

void releaseLock (int lockFd) {
    flock (lockFd, LOCK_UN);
    close (lockFd);
}

void restart_process(char **args, int lockFd)
{
#if 0
    int childpid;

    childpid = vfork ();
    if (childpid < 0) {
        perror ("fork failed");
    } else if (childpid  == 0) {
        //printf ("new process %d", getpid());
        int rv = execve (args[0], args, NULL);
        if (rv == -1) {
            perror ("execve");
            exit (EXIT_FAILURE);
        }

    } else {
        releaseLock(lockFd);
        //sleep (5);
        //printf ("killing %d\n", getpid());
        //kill (getpid (), SIGTERM);
    }
#endif
    releaseLock(lockFd);
    execve(args[0], args, NULL);
}

void daemonize(const char* path)
{
#ifndef __MINGW32__
    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0)
    {
        FILE *file = fopen(path, "w");
        if (file == NULL) fprintf(stderr, "Invalid pid file\n");

        fprintf(file, "%d", pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
    {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0)
    {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif
}

//http://stackoverflow.com/questions/664014/what-integer-hash-function-are-good-that-accepts-an-integer-hash-key
unsigned int hash(unsigned int x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x);
    return x;
    //hash(i)=i*2654435761 mod 2^32
}
 
//http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
void encry (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
 
void decry (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void generate_key(uint32_t* k)
{
    int i = 3, n = 16;
    time_t t;
    
    time(&t);
    k[i] = (uint32_t)t;
    k[i] = (k[i]+n-1) / n;
    k[i] = hash(k[i]);
}

void en_test() {
    uint32_t v[] = {0x12345678, 0x98765432};
    uint32_t k[] = {0x53726438, 0x89742910, 0x47492018, 0x0};

    generate_key(k);
    fprintf(stderr, "first v0=%x v1=%x k3=%x\n", v[0], v[1], k[3]);

    encry(v, k);
    sleep(2);
    generate_key(k);
    fprintf(stderr, "second v0=%x v1=%x k3=%x\n", v[0], v[1], k[3]);

    decry(v, k);
    fprintf(stderr, "third v0=%x v1=%x\n", v[0], v[1]);

}

int main (int argc, char **argv)
{
#if 0
    char *pid_path = "/tmp/ss-test.pid";

    int fd = acquireLock(pid_path);
    while(fd < 0) {
        fprintf(stderr, "locked\n");
        fd = acquireLock(pid_path);
    }
#endif

    //daemonize(pid_path);
    en_test();

    loop = EV_DEFAULT;
    // initialise an io watcher, then start it
    // this one will watch for stdin to become readable
    setnonblock(0);
    ev_io_init(&stdin_watcher, stdin_cb, /*STDIN_FILENO*/ 0, EV_READ);

    connection_new(EV_A_ "/tmp/ss-mgmt.sock");

    // now wait for events to arrive
    ev_loop(EV_A_ 0);

    //restart_process(argv, fd);

    // unloop was called, so exit
    return 0;
}
