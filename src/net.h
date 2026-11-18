/* net.h —— UDP 多播 socket 与本机网卡探测 */
#ifndef MC_NET_H
#define MC_NET_H

#include <stddef.h>

#define MC_RCVBUF (4 * 1024 * 1024)

/* 默认路由所用网卡的 IP（UDP connect 不会真的发包），失败写入 "0.0.0.0" */
void guess_local_ip(char out[16]);
/* 列出本机非回环 IPv4 地址，返回个数 */
int list_local_ips(char ips[][16], int max);
int is_multicast_addr(const char *addr);

/* 创建一个可收可发的多播 socket，失败返回 -1 并把原因写入 err */
int open_multicast_socket(const char *group, int port, const char *iface, int ttl,
                          char *err, size_t errlen);
void leave_multicast_group(int fd, const char *group, const char *iface);

#endif
