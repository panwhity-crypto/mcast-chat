/*
 * members.h —— 应用层组成员表
 *
 * 多播协议本身不提供"组里有谁"（IGMP 只告诉路由器"这个网段有人要收"），
 * 因此成员列表完全由应用层维护：
 *   - 上线发 HELLO，之后每 HEARTBEAT_INTERVAL 秒发一次 HEARTBEAT；
 *   - 超过 MEMBER_TIMEOUT 秒没有心跳即判定离线；主动退出发 BYE。
 */
#ifndef MC_MEMBERS_H
#define MC_MEMBERS_H

#include <openssl/evp.h>
#include <stdint.h>

#include "protocol.h"

#define MAX_MEMBERS 64
#define MAX_BANNED 64
#define HEARTBEAT_INTERVAL 2.0
#define MEMBER_TIMEOUT 6.0

typedef struct {
    int used;
    uint8_t id[MC_ID_LEN];
    char name[MC_MAX_NAME + 1];
    EVP_PKEY *pub;
    double since;     /* 该节点自报的上线时间（选举用） */
    char addr[16];    /* 最近一次收到其数据包的源 IP */
    int is_admin;
    uint32_t epoch;   /* 该成员当前持有的组密钥版本 */
    int has_key;
    double last_seen; /* 单调时钟 */
    double last_key_sent; /* 管理员上次给它发密钥的时间（限速重发） */
} member;

typedef struct {
    member m[MAX_MEMBERS];
    uint8_t banned[MAX_BANNED][MC_ID_LEN];
    int nbanned;
} member_table;

/* 选举顺序比较：上线早者优先，相同比较 ID。a 优先返回 <0 */
int rank_cmp(double since_a, const uint8_t *id_a, double since_b, const uint8_t *id_b);

member *mt_find(member_table *t, const uint8_t id[MC_ID_LEN]);
member *mt_add(member_table *t, const uint8_t id[MC_ID_LEN]); /* 满了返回 NULL */
void mt_remove(member *m);
int mt_count(const member_table *t);
int mt_is_banned(const member_table *t, const uint8_t id[MC_ID_LEN]);
void mt_ban(member_table *t, const uint8_t id[MC_ID_LEN]);
/* 声称是管理员的成员中排序最靠前者，没有返回 NULL */
member *mt_first_admin(member_table *t);
/* 按选举顺序排序后的成员指针，返回个数 */
int mt_sorted(member_table *t, member **out, int max);

#endif
