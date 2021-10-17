#define _GNU_SOURCE	   /* See feature_test_macros(7) */
#include <fcntl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "net.h"
#include "cJSON.h"
#include "list.h"

//获取本机ip
int getip(char *ip)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if(getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL;ifa = ifa->ifa_next) 
    {
        if(ifa->ifa_addr == NULL)
            continue;
        family = ifa->ifa_addr->sa_family;

        if(!strcmp(ifa->ifa_name, "lo"))
            continue;
        if(family == AF_INET)
        {
            s = getnameinfo(ifa->ifa_addr, 
                    (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), 
                    ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if(s != 0)
                return -1;
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    return -1;
}

//连接服务器
int server_connect(int type, const char *server_ip, const char *server_port)
{
    short port = 0;
    int sock_fd = 0;
    struct sockaddr_in server_addr;

    if(INADDR_NONE == (server_addr.sin_addr.s_addr = inet_addr(server_ip)))
    {
        printf("err serverip:%s\n", server_ip);
        return -1;
    }


    port = (short)atoi(server_port);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if(type == 0)
    {
        if((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            printf("tcp socket error,ip:%s,port:%d\n", server_ip, port);
            return -1;
        }
    }
    else if(type == 1)
    {
        if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
            printf("udp socket error,ip:%s,port:%d\n", server_ip, port);
            return -1;
        }
    }

    if(connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)) < 0)
    {
        close(sock_fd);
        printf("socket connect error,ip:%s,port:%d\n", server_ip, port);
        return -1;
    }

    return sock_fd;
}

//查找本地可用端口
short find_free_port(int type)
{
    int fd;
    short port;
    struct sockaddr_in addr;

    if(type == 0)
        fd = socket(AF_INET, SOCK_STREAM, 0);
    else if(type == 1)
        fd = socket(AF_INET, SOCK_DGRAM, 0);
    else
        return -1;

    addr.sin_family = AF_INET;

    for (port = 10000; port < 20000; ++port) 
    {
        addr.sin_port = htons(port);
        inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);

        if(bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0)
            continue;
        else
        {
            close(fd);
            return port;
        }
    }

    close(fd);
    return -1;
}

//创建server连接
int create_server_socket(int type, const char *ip, const char *port)
{
    struct sockaddr_in serverAddr, clientAddr;
    int sock_fd, connfd, sockAddrSize = sizeof(struct sockaddr_in),addreuse = 1;

    if(type == 0)
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    else if(type == 1)
        sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    else
        return -1;

    if(sock_fd < 0)
    {
        printf("cmd server create socket err\n");
        return -1;
    }
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &addreuse, sizeof(int)) < 0)
    {
        perror("setsockopt");
        close(sock_fd);
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((short)atoi(port));
    inet_pton(AF_INET, ip, &serverAddr.sin_addr);

    if(bind(sock_fd, (struct sockaddr*)&serverAddr, sizeof(struct sockaddr_in)))
    {
        perror("setsockopt");
        close(sock_fd);
        return -1;
    }
    
    if(type == 0)
        listen(sock_fd, 20);
    return sock_fd;
}

//sock读取数据
int Readn(int fd,char *buf,size_t count)
{
    if(fd < 0) return -1;
    int ret = 0;
    size_t left = count;

    while(left > 0)
    {
        if((ret = read(fd, buf, left)) < 0)
        {
            if( errno == EINTR)
                continue;
            perror("readn error");
            if(left == count)
                return -1;
            break;
        }
        else if(ret == 0)
            return -1;
        else
        {
            buf += ret;
            left -= ret;
            if(buf[-5] == 'T' && buf[-4] == 'A' && buf[-3] == 'I' && buf[-2] == 'L' && buf[-1] == '\n')
                break;
        }
    }
    return count - left;
}

//sock 写入数据
int Writen(int fd, const char *buf, size_t count)
{
    if(fd < 0) return -1;

    int ret = 0;
    size_t left = count;

    while(left > 0)
    {
        if((ret = write(fd, buf, left)) < 0)
        {
            if(errno == EINTR)
                continue;

            perror("writen error");
            if(left == count)
                return -1;
            break;
        }
        else if(ret == 0)
            break;
        else
        {
            buf += ret;
            left -= ret;
        }
    }

    return count - left;
}

//解析数据
int parse_msg(const char *data, pmap_s *pmap)
{
    cJSON *msg = NULL, *ele = NULL;

    msg = cJSON_Parse(data);
    if(!msg)
        return -1;
    ele = cJSON_GetObjectItem(msg, "cmd");
    if(!ele)
        goto ERR;
    pmap->cmd = ele->valueint;
    ele = cJSON_GetObjectItem(msg, "type");
    if(!ele)
        goto ERR;
    pmap->type = ele->valueint;
    ele = cJSON_GetObjectItem(msg, "server_ip");
    if(!ele)
        goto ERR;
    strncpy(pmap->server_ip, ele->valuestring, sizeof(pmap->server_ip));
    ele = cJSON_GetObjectItem(msg, "server_port");
    if(!ele)
        goto ERR;
    strncpy(pmap->server_port, ele->valuestring, sizeof(pmap->server_port));

    cJSON_Delete(msg);
    return 0;
ERR:
    printf("err msg %s\n", data);
    cJSON_Delete(msg);
    return -1;
}

//接收消息
int recv_msg(int fd, pmap_s *pmap)
{
    char buf[4096];

    memset(buf, 0, sizeof(buf));
    if(-1 == Readn(fd, buf, sizeof(buf)))
        return -2;
    if(parse_msg(buf, pmap))
        return -1;
    return 0;
}

//发送消息
int  send_msg(int fd, const pmap_result_s *pmap)
{
    cJSON *msg = NULL;
    char *tbuf;

    msg = cJSON_CreateObject();

    cJSON_AddNumberToObject(msg, "result", pmap->result);
    cJSON_AddStringToObject(msg, "ip", pmap->ip);
    cJSON_AddStringToObject(msg, "port", pmap->port);

    tbuf = cJSON_Print(msg);

    Writen(fd, tbuf, strlen(tbuf));
    Writen(fd, "TAIL\n", strlen("TAIL\n"));

    free(tbuf);
    cJSON_Delete(msg);

    return 0;
}

typedef struct _conn_s
{
    list_node node;
    pthread_t thread_id;
    int server_fd;
    int local_fd;
    int connfd;
    int local_port;
    int type;
}conn_s;

static list_node conn_list = LIST_HEAD_INIT(conn_list);
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

//代理
void* proxy_handle(void *args)
{
    int retval;
    struct timeval tv;
    fd_set rfds;
    struct sockaddr_in clientAddr;
    socklen_t sockAddrSize = sizeof(struct sockaddr_in);
    char buf[4096];
    conn_s *con = args;
    
    pthread_mutex_lock(&mutex);
    con->thread_id = pthread_self();
    list_add_next(&conn_list, &con->node);
    pthread_mutex_unlock(&mutex);

    if(con->type == 0)
    {
        while(1)
        {
            FD_ZERO(&rfds);
            FD_SET(con->local_fd, &rfds);
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            retval = select(con->local_fd + 1, &rfds, NULL, NULL, &tv);
            if(retval == -1)
                perror("select");
            else if(retval)
            {
                if((con->connfd = accept(con->local_fd, (struct sockaddr*)&clientAddr, (socklen_t*)&sockAddrSize)) < 0)
                {
                    printf("accept failed\n");
                    continue;
                }
                close(con->local_fd);
                break;
            }
            else
            {
                if(con->type == -1)
                {
                    close(con->server_fd);
                    close(con->local_fd);
                    return NULL;
                }
            }
        }
    }
    else //udp不需要accept
        con->connfd = con->local_fd;

    int pipefd[2];
    pipe(pipefd);
    while(1)
    {
        FD_ZERO(&rfds);
        FD_SET(con->connfd, &rfds);
        FD_SET(con->server_fd, &rfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        retval = select((con->connfd > con->server_fd ? con->connfd : con->server_fd) + 1, 
                &rfds, NULL, NULL, &tv);
        if(retval == -1)
            perror("select");
        else if(retval)
        {
            if(FD_ISSET(con->connfd, &rfds))
            {
                if(splice(con->connfd, NULL, pipefd[1], NULL, 65535, SPLICE_F_MORE) <= 0)
                    break;
                if(splice(pipefd[0], NULL, con->server_fd, NULL, 65535, SPLICE_F_MORE) <= 0)
                    break;
            }

            if(FD_ISSET(con->server_fd, &rfds))
            {
                if(splice(con->server_fd, NULL, pipefd[1], NULL, 65535, SPLICE_F_MORE) <= 0)
                    break;
                if(splice(pipefd[0], NULL, con->connfd, NULL, 65535, SPLICE_F_MORE) <= 0)
                    break;
            }
        }
        else
        {
            if(con->type == -1)
            {
                close(con->server_fd);
                close(con->connfd);
                return NULL;
            }
        }
    }

    pthread_mutex_lock(&mutex);
    list_del(&con->node);
    pthread_mutex_unlock(&mutex);

    close(con->server_fd);
    close(con->connfd);
    free(con);
    return NULL;
}

//建立端口映射
int  proxy_map(int type, short local_port, const char *server_ip, const char *server_port)
{
    pthread_t thread_id;
    conn_s *con;
    char ip[64];
    char port[20];

    con = malloc(sizeof(*con));

    //连接目标服务器
    con->server_fd = server_connect(type, server_ip, server_port);
    if(con->server_fd < 0)
    {
        free(con);
        printf("connect server err, ip:%s,port:%s\n", server_ip, server_port);
        return -1;
    }

    //创建本地监听服务
    getip(ip);
    snprintf(port, sizeof(port), "%d", (int)local_port);
    con->local_fd = create_server_socket(type, ip, port);
    if(con->local_fd < 0)
    {
        close(con->local_fd);
        free(con);
        printf("create local sock err, ip:%s,port:%s\n", ip, port);
        return -1;
    }
    con->type = type;
    con->local_port = local_port;
    con->connfd = -1;

    pthread_create(&thread_id, NULL, proxy_handle, (void*)con);
    return 0;
}

//端口去映射
int  proxy_unmap(int type, short local_port)
{
    list_node *pos;
    conn_s *con = NULL;

    pthread_mutex_lock(&mutex);
    list_foreach(pos, &conn_list)
    {
        con = (conn_s*)pos;
        if(con->type == type && con->local_port == local_port)
        {
            con->type = -1;
            list_del(&con->node);
            break;
        }
    }
    pthread_mutex_unlock(&mutex);
    if(con)
        pthread_join(con->thread_id, NULL);
    return 0;
}









