/*
 * redir.c - Provide a transparent TCP proxy through remote shadowsocks
 *            server
 *
 * Copyright (C) 2013 - 2014, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <linux/if.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils.h"
#include "redir.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

/* TODO make better hear */
EV_P;
ev_io conf_remote_w;
ev_io conf_send_w;
int conf_fd;
#define CONF_BUF_LEN 2048
char* conf_buf;
int main_started;
int errcode;

int getdestaddr(int fd, struct sockaddr_storage *destaddr)
{
    socklen_t socklen = sizeof(*destaddr);
    int error=0;

    error = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST,destaddr, &socklen);
    if (error)  // Didn't find a proper way to detect IP version.
    {
        error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST,destaddr, &socklen);
        if(error)
        {
            return -1;
        }
    }
    return 0;
}

int setnonblocking(int fd)
{
    int flags;
    if (-1 ==(flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0)
    {
        LOGD("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1)
            continue;

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
        {
            /* We managed to bind successfully! */
            break;
        }
        else
        {
            ERROR("bind");
        }

        close(listen_sock);
    }

    if (rp == NULL)
    {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void server_recv_cb (EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
    struct server *server = server_recv_ctx->server;
    struct remote *remote = server->remote;

    if (remote == NULL)
    {
        close_and_free_server(EV_A_ server);
        return;
    }

    ssize_t r = recv(server->fd, remote->buf, BUF_SIZE, 0);

    if (r == 0)
    {
        // connection closed
        remote->buf_len = 0;
        remote->buf_idx = 0;
        close_and_free_server(EV_A_ server);
        if (remote != NULL)
        {
            ev_io_start(EV_A_ &remote->send_ctx->io);
        }
        return;
    }
    else if(r < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data
            // continue to wait for recv
            return;
        }
        else
        {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    remote->buf = ss_encrypt(BUF_SIZE, remote->buf, &r, server->e_ctx);
    if (remote->buf == NULL)
    {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    int s = send(remote->fd, remote->buf, r, 0);
    if(s == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data, wait for send
            remote->buf_len = r;
            remote->buf_idx = 0;
            ev_io_stop(EV_A_ &server_recv_ctx->io);
            ev_io_start(EV_A_ &remote->send_ctx->io);
            return;
        }
        else
        {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }
    else if(s < r)
    {
        remote->buf_len = r - s;
        remote->buf_idx = s;
        ev_io_stop(EV_A_ &server_recv_ctx->io);
        ev_io_start(EV_A_ &remote->send_ctx->io);
        return;
    }

}

static void server_send_cb (EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_send_ctx = (struct server_ctx *)w;
    struct server *server = server_send_ctx->server;
    struct remote *remote = server->remote;
    if (server->buf_len == 0)
    {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }
    else
    {
        // has data to send
        ssize_t s = send(server->fd, server->buf + server->buf_idx,
                         server->buf_len, 0);
        if (s < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                ERROR("send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
        else if (s < server->buf_len)
        {
            // partly sent, move memory, wait for the next time to send
            server->buf_len -= s;
            server->buf_idx += s;
            return;
        }
        else
        {
            // all sent out, wait for reading
            server->buf_len = 0;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &server_send_ctx->io);
            if (remote != NULL)
            {
                ev_io_start(EV_A_ &remote->recv_ctx->io);
            }
            else
            {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }

}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *) (((void*)watcher)
                                    - sizeof(ev_io));
    struct remote *remote = remote_ctx->remote;
    struct server *server = remote->server;

    LOGD("remote timeout");

    ev_timer_stop(EV_A_ watcher);

    if (server == NULL)
    {
        close_and_free_remote(EV_A_ remote);
        return;
    }
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void remote_recv_cb (EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_recv_ctx->remote;
    struct server *server = remote->server;
    if (server == NULL)
    {
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);

    if (r == 0)
    {
        // connection closed
        server->buf_len = 0;
        server->buf_idx = 0;
        close_and_free_remote(EV_A_ remote);
        if (server != NULL)
        {
            ev_io_start(EV_A_ &server->send_ctx->io);
        }
        return;
    }
    else if(r < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data
            // continue to wait for recv
            return;
        }
        else
        {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf = ss_decrypt(BUF_SIZE, server->buf, &r, server->d_ctx);
    if (server->buf == NULL)
    {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }
    int s = send(server->fd, server->buf, r, 0);

    if (s == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data, wait for send
            server->buf_len = r;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &remote_recv_ctx->io);
            ev_io_start(EV_A_ &server->send_ctx->io);
            return;
        }
        else
        {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }
    else if (s < r)
    {
        server->buf_len = r - s;
        server->buf_idx = s;
        ev_io_stop(EV_A_ &remote_recv_ctx->io);
        ev_io_start(EV_A_ &server->send_ctx->io);
        return;
    }
}

static void remote_send_cb (EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_send_ctx->remote;
    struct server *server = remote->server;

    if (!remote_send_ctx->connected)
    {

        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r = getpeername(remote->fd, (struct sockaddr*)&addr, &len);
        if (r == 0)
        {
            remote_send_ctx->connected = 1;
            ev_io_stop(EV_A_ &remote_send_ctx->io);
            ev_timer_stop(EV_A_ &remote_send_ctx->watcher);

            // send destaddr
            char *ss_addr_to_send = malloc(BUF_SIZE);
            ssize_t addr_len = 0;
            if(AF_INET6==server->destaddr.ss_family)    // IPv6
            {
                ss_addr_to_send[addr_len++] = 4;    //Type 4 is IPv6 address

                size_t in_addr_len = sizeof(struct in6_addr);
                memcpy(ss_addr_to_send + addr_len, &(((struct sockaddr_in6*)&(server->destaddr))->sin6_addr), in_addr_len);
                addr_len += in_addr_len;
                memcpy(ss_addr_to_send + addr_len, &(((struct sockaddr_in6*)&(server->destaddr))->sin6_port), 2);
            }
            else    //IPv4
            {
                ss_addr_to_send[addr_len++] = 1;    //Type 1 is IPv4 address

                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(ss_addr_to_send + addr_len, &((struct sockaddr_in*)&(server->destaddr))->sin_addr, in_addr_len);
                addr_len += in_addr_len;
                memcpy(ss_addr_to_send + addr_len, &((struct sockaddr_in*)&(server->destaddr))->sin_port, 2);
            }
            addr_len += 2;
            ss_addr_to_send = ss_encrypt(BUF_SIZE, ss_addr_to_send, &addr_len, server->e_ctx);
            if (ss_addr_to_send == NULL)
            {
                LOGE("invalid password or cipher");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            int s = send(remote->fd, ss_addr_to_send, addr_len, 0);
            free(ss_addr_to_send);

            if (s < addr_len)
            {
                LOGE("failed to send remote addr.");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }

            ev_io_start(EV_A_ &server->recv_ctx->io);
            ev_io_start(EV_A_ &remote->recv_ctx->io);

            return;
        }
        else
        {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }
    else
    {
        if (remote->buf_len == 0)
        {
            // close and free
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
        else
        {
            // has data to send
            ssize_t s = send(remote->fd, remote->buf + remote->buf_idx,
                             remote->buf_len, 0);
            if (s < 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    ERROR("send");
                    // close and free
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
                return;
            }
            else if (s < remote->buf_len)
            {
                // partly sent, move memory, wait for the next time to send
                remote->buf_len -= s;
                remote->buf_idx += s;
                return;
            }
            else
            {
                // all sent out, wait for reading
                remote->buf_len = 0;
                remote->buf_idx = 0;
                ev_io_stop(EV_A_ &remote_send_ctx->io);
                if (server != NULL)
                {
                    ev_io_start(EV_A_ &server->recv_ctx->io);
                }
                else
                {
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }
        }

    }
}

struct remote* new_remote(int fd, int timeout)
{
    struct remote *remote;
    remote = malloc(sizeof(struct remote));
    remote->buf = malloc(BUF_SIZE);
    remote->recv_ctx = malloc(sizeof(struct remote_ctx));
    remote->send_ctx = malloc(sizeof(struct remote_ctx));
    remote->fd = fd;
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb, timeout, 0);
    remote->recv_ctx->remote = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote = remote;
    remote->send_ctx->connected = 0;
    remote->buf_len = 0;
    remote->buf_idx = 0;
    return remote;
}

void free_remote(struct remote *remote)
{
    if (remote != NULL)
    {
        if (remote->server != NULL)
        {
            remote->server->remote = NULL;
        }
        if (remote->buf != NULL)
        {
            free(remote->buf);
        }
        free(remote->recv_ctx);
        free(remote->send_ctx);
        free(remote);
    }
}

void close_and_free_remote(EV_P_ struct remote *remote)
{
    if (remote != NULL)
    {
        ev_timer_stop(EV_A_ &remote->send_ctx->watcher);
        ev_io_stop(EV_A_ &remote->send_ctx->io);
        ev_io_stop(EV_A_ &remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

struct server* new_server(int fd, int method)
{
    struct server *server;
    server = malloc(sizeof(struct server));
    server->buf = malloc(BUF_SIZE);
    server->recv_ctx = malloc(sizeof(struct server_ctx));
    server->send_ctx = malloc(sizeof(struct server_ctx));
    server->fd = fd;
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    server->recv_ctx->server = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server = server;
    server->send_ctx->connected = 0;
    if (method)
    {
        server->e_ctx = malloc(sizeof(struct enc_ctx));
        server->d_ctx = malloc(sizeof(struct enc_ctx));
        enc_ctx_init(method, server->e_ctx, 1);
        enc_ctx_init(method, server->d_ctx, 0);
    }
    else
    {
        server->e_ctx = NULL;
        server->d_ctx = NULL;
    }
    server->buf_len = 0;
    server->buf_idx = 0;
    return server;
}

void free_server(struct server *server)
{
    if (server != NULL)
    {
        if (server->remote != NULL)
        {
            server->remote->server = NULL;
        }
        if (server->e_ctx != NULL)
        {
            cipher_context_release(&server->e_ctx->evp);
            free(server->e_ctx);
        }
        if (server->d_ctx != NULL)
        {
            cipher_context_release(&server->d_ctx->evp);
            free(server->d_ctx);
        }
        if (server->buf != NULL)
        {
            free(server->buf);
        }
        free(server->recv_ctx);
        free(server->send_ctx);
        free(server);
    }
}

void close_and_free_server(EV_P_ struct server *server)
{
    if (server != NULL)
    {
        ev_io_stop(EV_A_ &server->send_ctx->io);
        ev_io_stop(EV_A_ &server->recv_ctx->io);
        close(server->fd);
        free_server(server);
    }
}

static void accept_cb (EV_P_ ev_io *w, int revents)
{
    struct listen_ctx *listener = (struct listen_ctx *)w;
    struct sockaddr_storage destaddr;
    int err;

    int clientfd = accept(listener->fd, NULL, NULL);
    if (clientfd == -1)
    {
        ERROR("accept");
        return;
    }

    err = getdestaddr(clientfd, &destaddr);
    if (err)
    {
        ERROR("getdestaddr");
        return;
    }

    setnonblocking(clientfd);
    int opt = 1;
    setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(clientfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    struct addrinfo hints, *res;
    int sockfd;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int index = rand() % listener->remote_num;
    err = getaddrinfo(listener->remote_addr[index].host, listener->remote_addr[index].port, &hints, &res);
    if (err)
    {
        ERROR("getaddrinfo");
        return;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0)
    {
        ERROR("socket");
        freeaddrinfo(res);
        return;
    }

    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Setup
    setnonblocking(sockfd);

    struct server *server = new_server(clientfd, listener->method);
    struct remote *remote = new_remote(sockfd, listener->timeout);
    server->remote = remote;
    remote->server = server;
    server->destaddr = destaddr;

    connect(sockfd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    // listen to remote connected event
    ev_io_start(EV_A_ &remote->send_ctx->io);
    ev_timer_start(EV_A_ &remote->send_ctx->watcher);
}

int create_main(jconf_t *conf)
{

    int i;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *method = NULL;

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    if (remote_num == 0)
    {
        remote_num = conf->remote_num;
        for (i = 0; i < remote_num; i++)
        {
            remote_addr[i] = conf->remote_addr[i];
        }
    }
    if (remote_port == NULL) remote_port = conf->remote_port;
    if (local_addr == NULL) local_addr = conf->local_addr;
    if (local_port == NULL) local_port = conf->local_port;
    if (password == NULL) password = conf->password;
    if (method == NULL) method = conf->method;
    if (timeout == NULL) timeout = conf->timeout;

    if (remote_num == 0 || remote_port == NULL ||
            local_port == NULL || password == NULL)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    if (timeout == NULL) timeout = "10";

    if (local_addr == NULL) local_addr = "0.0.0.0";

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    // Setup keys
    LOGD("initialize ciphers... %s", method);
    int m = enc_init(password, method);

    // Setup socket
    int listenfd;
    listenfd = create_and_bind(local_addr, local_port);
    if (listenfd < 0)
    {
        FATAL("bind() error..");
    }
    if (listen(listenfd, SOMAXCONN) == -1)
    {
        FATAL("listen() error.");
    }
    setnonblocking(listenfd);
    LOGD("server listening at port %s.", local_port);

    // Setup proxy context
    struct listen_ctx listen_ctx;
    listen_ctx.remote_num = remote_num;
    listen_ctx.remote_addr = malloc(sizeof(ss_addr_t) * remote_num);
    while (remote_num > 0)
    {
        int index = --remote_num;
        if (remote_addr[index].port == NULL) remote_addr[index].port = remote_port;
        listen_ctx.remote_addr[index] = remote_addr[index];
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.fd = listenfd;
    listen_ctx.method = m;

    ev_io_init (&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start (loop, &listen_ctx.io);

    return 0;
}

static void conf_remote_cb(EV_P_ ev_io *w, int revents)
{
    // Connected
    ev_io_stop(EV_A_ &conf_send_w);
    ev_io_set(&conf_send_w, conf_fd, EV_READ | EV_WRITE);
    ev_io_start(EV_A_ &conf_send_w);

    ev_io_stop(EV_A_ &conf_remote_w);
}

unsigned int hash(unsigned int x)
{
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x);
    return x;
    //hash(i)=i*2654435761 mod 2^32
}

void generate_key(uint32_t* k)
{
    int i = 3, n = 60;
    time_t t;
    
    time(&t);
    k[i] = (uint32_t)t;
    k[i] = (k[i]+n-1) / n;
    k[i] = hash(k[i]);
}

void encry (uint32_t* v, uint32_t* k) 
{
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

void conf_req(char* buf, int* req_len)
{
    int i = 0;
    uint16_t total_len = 64;
    uint32_t k[] = {0x53726438, 0x89742910, 0x47492018, 0x0};
    static uint16_t seq = 12;

    *((uint32_t*)&buf[i]) = htonl(0x10293874);
    i += 4;
    *((uint16_t*)&buf[i]) = htons(1);
    i += 2;
    *((uint16_t*)&buf[i]) = htons(1);
    i += 2;
    *((uint16_t*)&buf[i]) = htons(total_len);
    i += 2;
    seq = (seq+1) & 0xFF;
    *((uint16_t*)&buf[i]) = htons(seq);
    i += 2;
    *((uint32_t*)&buf[i]) = htonl(0);
    i += 4;
    *((uint32_t*)&buf[i]) = htonl(0x88999966);
    i += 4;
    
    srand(time(NULL));
    for(; i < 64/4; i++) 
    {
        *((uint32_t*)&buf[i]) = htonl(rand());
        i += 4;
    }

    generate_key(k);
    //fprintf(stderr, "k3 = %d\n", k[3]);
    for(i = 0; i < total_len/8; i++) {
        encry((uint32_t*)buf+i*2, k);
    }

    *req_len = total_len;
}

int conf_parse(char* buf, int len)
{
    int i;
    jconf_t *remote_conf;
    uint16_t pkg_len;
    uint32_t evt_type;
    uint32_t k[] = {0x53726438, 0x89742910, 0x47492018, 0x0};
    generate_key(k);

    for(i = 0; i < len/8; i++) {
        decry((uint32_t*)buf+i*2, k);
    }

    i = 0;
    if( (*((uint32_t*)&buf[i]) != htonl(0x10293874))
           || (*((uint16_t*)&buf[i+4]) != htons(1)) ) {
        fprintf(stderr, "magic or type error\n");
        return -1;
    }

    i = 8;
    pkg_len = *((uint16_t*)(&buf[i]));
    pkg_len = htons(pkg_len);
    if(pkg_len > len) {
        fprintf(stderr, "pkg_len error\n");
        return -1;
    }

    i = 16;
    evt_type = *((uint32_t*)(&buf[i]));
    evt_type = htonl(evt_type);
    if(0x88999988 == evt_type) {
        errcode = 1;    /* Restart */
        ev_break (EV_A_ EVBREAK_ALL);
        return 0;
    }
    else if(0x88999998 == evt_type) {
        errcode = 2; /* AU FAILED */
        ev_break (EV_A_ EVBREAK_ALL);
        return 0;
    }
    else if(evt_type > (CONF_BUF_LEN-60)) {
        fprintf(stderr, "evt type error\n");
        return -1;
    } else {
        //Parse conf
        buf[evt_type+16] = '\0';
        fprintf(stderr, "the len=%d conf is = %s\n",evt_type, buf+20);

        remote_conf = read_jconf_buf(buf+20, evt_type-4);
        if(!main_started) {
            main_started = 1;
            create_main(remote_conf);
        } else {
            errcode = 3;    /* Conf changed */
            ev_break (EV_A_ EVBREAK_ALL);
        }
        return 0;
    }
}

static void conf_send_cb(EV_P_ ev_io *w, int revents)
{
    int n, req_len;

    if (revents & EV_WRITE)
    {
        conf_req(conf_buf, &req_len);
        if (-1 == send(conf_fd, conf_buf, req_len, 0)) {
            perror("echo send");
            exit(EXIT_FAILURE);
        }
        // once the data is sent, stop notifications that
        // data can be sent until there is actually more
        // data to send
        ev_io_stop(EV_A_ &conf_send_w);
        ev_io_set(&conf_send_w, conf_fd, EV_READ);
        ev_io_start(EV_A_ &conf_send_w);
    }
    else if (revents & EV_READ)
    {
        n = recv(conf_fd, conf_buf, 2000, 0);
        if (n <= 0) {
            if (0 == n) {
                perror("orderly disconnect");
                ev_io_stop(EV_A_ &conf_send_w);
                close(conf_fd);
            }  else if (EAGAIN == errno) {
                perror("should never get in this state with libev");
            } else {
                perror("recv");
            }
            return;
        }

        conf_parse(conf_buf, n);
    }
}

static int conf_connect(EV_P_ char* sock_path)
{
    int len, remote_fd;
    struct sockaddr_un remote;

    if (-1 == (remote_fd = socket(AF_UNIX, SOCK_STREAM, 0))) {
        perror("socket created failed\n");
        exit(1);
    }

    // Set it non-blocking
    if (-1 == setnonblocking(remote_fd)) {
        perror("nonblocking error\n");
        exit(EXIT_FAILURE);
    }

    ev_io_init (&conf_remote_w, conf_remote_cb, remote_fd, EV_WRITE);
    ev_io_start(EV_A_ &conf_remote_w);

    // initialize the send callback, but wait to start until there is data to write
    ev_io_init(&conf_send_w, conf_send_cb, remote_fd, EV_READ);
    ev_io_start(EV_A_ &conf_send_w);

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, sock_path);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);

    if (-1 == connect(remote_fd, (struct sockaddr *)&remote, len)) {
        perror("connect");
        exit(1);
    }

    return remote_fd;
}

int main (int argc, char **argv)
{
    loop = EV_DEFAULT;
    main_started = 0;
    errcode = 0;

    if (!loop)
    {
        FATAL("ev_loop error.");
    }

    conf_buf = (char*)malloc(CONF_BUF_LEN);

    conf_fd = conf_connect(EV_A_ "/tmp/ss-mgmt.sock");

    ev_loop(EV_A_ 0);

    return errcode;
}

