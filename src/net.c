#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

void guess_local_ip(char out[16])
{
    strcpy(out, "0.0.0.0");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return;
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons(1)};
    inet_pton(AF_INET, "10.255.255.255", &dst.sin_addr);
    if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
        struct sockaddr_in me;
        socklen_t len = sizeof(me);
        if (getsockname(s, (struct sockaddr *)&me, &len) == 0)
            inet_ntop(AF_INET, &me.sin_addr, out, 16);
    }
    close(s);
}

int list_local_ips(char ips[][16], int max)
{
    int n = 0;
    char primary[16];
    guess_local_ip(primary);
    if (strcmp(primary, "0.0.0.0") != 0 && n < max)
        strcpy(ips[n++], primary);
    struct ifaddrs *ifs, *it;
    if (getifaddrs(&ifs) == 0) {
        for (it = ifs; it && n < max; it = it->ifa_next) {
            if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET || (it->ifa_flags & IFF_LOOPBACK))
                continue;
            char buf[16];
            inet_ntop(AF_INET, &((struct sockaddr_in *)it->ifa_addr)->sin_addr, buf, sizeof(buf));
            int dup = 0;
            for (int i = 0; i < n; i++)
                dup |= strcmp(ips[i], buf) == 0;
            if (!dup)
                strcpy(ips[n++], buf);
        }
        freeifaddrs(ifs);
    }
    if (n == 0 && max > 0)
        strcpy(ips[n++], "0.0.0.0");
    return n;
}

int is_multicast_addr(const char *addr)
{
    struct in_addr a;
    if (inet_pton(AF_INET, addr, &a) != 1)
        return 0;
    return IN_MULTICAST(ntohl(a.s_addr));
}

/*
 * - SO_REUSEADDR：允许同一台机器上多个实例绑定同一端口，多播包会复制给每个 socket；
 * - IP_ADD_MEMBERSHIP：在 iface 上加入多播组，内核随即发出 IGMP 成员报告；
 * - IP_MULTICAST_IF / TTL / LOOP：出口网卡、跳数，以及回环（同机实例互通）。
 */
int open_multicast_socket(const char *group, int port, const char *iface, int ttl,
                          char *err, size_t errlen)
{
    struct in_addr grp, ifa;
    if (!is_multicast_addr(group)) {
        snprintf(err, errlen, "%s 不是多播地址（应在 224.0.0.0 ~ 239.255.255.255）", group);
        return -1;
    }
    inet_pton(AF_INET, group, &grp);
    if (inet_pton(AF_INET, iface, &ifa) != 1) {
        snprintf(err, errlen, "网卡地址 %s 不合法", iface);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        snprintf(err, errlen, "socket: %s", strerror(errno));
        return -1;
    }
    int one = 1, rcvbuf = MC_RCVBUF;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* 绑定 INADDR_ANY:port；收到的其他组/无关数据靠头部 magic 过滤 */
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                                .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        snprintf(err, errlen, "bind 端口 %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }

    struct ip_mreq mreq = {.imr_multiaddr = grp, .imr_interface = ifa};
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        snprintf(err, errlen, "加入多播组失败: %s（检查网卡 IP 是否正确）", strerror(errno));
        close(fd);
        return -1;
    }
    unsigned char t = (unsigned char)ttl, loop = 1;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof(ifa));
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &t, sizeof(t));
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    struct timeval tv = {.tv_sec = 0, .tv_usec = 300000}; /* recvfrom 超时，便于线程退出 */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

void leave_multicast_group(int fd, const char *group, const char *iface)
{
    struct ip_mreq mreq;
    inet_pton(AF_INET, group, &mreq.imr_multiaddr);
    inet_pton(AF_INET, iface, &mreq.imr_interface);
    setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
}
