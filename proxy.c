#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "net.h"



#define PROXY_PORT "9990"

void* so_handle(void *args)
{
    int fd = (int)args;
    char buf[4096];
    pmap_s pmap;
    pmap_result_s result;
    short port;

    while(1)
    {
        memset(buf, 0, sizeof(buf));
        memset(&result, 0, sizeof(result));
        
        int ret = recv_msg(fd, &pmap);
        if(-2 == ret)
            return NULL;
        else if(-1 == ret)
            goto ERR;


        if(pmap.cmd == 0)
        {
            port = find_free_port(pmap.type);
            if(port == -1)
                goto ERR;
            snprintf(result.port, sizeof(result.port), "%d", port);

            if(getip(result.ip))
                goto ERR;
            if(proxy_map(pmap.type, port, pmap.server_ip, pmap.server_port))
            {
                printf("proxy_map err localport:%d,server_ip:%s,server_port:%s\n", port, pmap.server_ip, pmap.server_port);
                goto ERR;
            }
            else
                printf("proxy_map success localport:%d,server_ip:%s,server_port:%s\n", port, pmap.server_ip, pmap.server_port);
        }
        else if(pmap.cmd == 1)
        {
            if(proxy_unmap(pmap.type, atoi(pmap.server_port)))
            {
                printf("proxy_unmap err type:%d,port:%d\n", pmap.type,  atoi(pmap.server_port));
                goto ERR;
            }
            else
                printf("proxy_unmap err type:%d,port:%d\n", pmap.type,  atoi(pmap.server_port));
        }

        result.result = 0;
        send_msg(fd, &result);
        continue;
ERR:
        result.result = 1;
        send_msg(fd, &result);
    }
}

int main(void)
{
    int i;
    struct sockaddr_in clientAddr;
    int sockfd, connfd, sockAddrSize = sizeof(struct sockaddr_in);
    char ip[64];

    getip(ip);
    sockfd = create_server_socket(0, ip, PROXY_PORT);
    if(sockfd < 0)
    {
        printf("create cmd sock err ip:%s,port:%s\n", ip, PROXY_PORT);
        return -1;
    }

    printf("listen sock:ip:%s,port:%s\n", ip, PROXY_PORT);

    while(1)
    {
        if((connfd = accept(sockfd, (struct sockaddr*)&clientAddr, (socklen_t*)&sockAddrSize)) < 0)
        {
            printf("accept() failed\n");
            continue;
        }
        pthread_t tid;
        pthread_create(&tid, NULL, so_handle, (void*)connfd);
    }
}





