#ifndef __NET_H__
#define __NET_H__

typedef struct
{
    int cmd; //0:map 1:unmap
    int type; //0:tcp 1:udp
    char server_ip[32];
    char server_port[32];
}pmap_s;

typedef struct
{
    int result;  //0:ok 1:fail
    char ip[32];
    char port[32];
}pmap_result_s;

short find_free_port();
int create_server_socket(int type, const char *ip, const char *port);
int send_msg(int fd, const pmap_result_s *pmap);
int recv_msg(int fd, pmap_s *pmap);
int getip(char *ip);
int proxy_map(int type, short local_port,const char *server_ip, const char *server_port);
int proxy_unmap(int type, short local_port);












#endif

