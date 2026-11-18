/*
 * node.h —— 聊天节点：一个对等节点的全部协议逻辑（不依赖任何界面）
 *
 * 所有节点运行同一份代码，直接向多播组收发数据，没有服务器转发。
 * "管理员"只是额外承担组密钥分发和删除成员的普通节点：
 *   - 启动后先监听 DISCOVERY_TIME 秒，听到管理员心跳就作为普通成员加入；
 *   - 没听到就自己成为管理员并生成第 1 版组密钥；
 *   - 管理员下线后，剩余成员中 (上线时间, ID) 最小者自动接任；
 *   - 同时出现两个管理员时，排序靠后的一方自动让位。
 *
 * 界面通过回调接收事件。回调在网络线程中调用，界面需自行切回主线程。
 */
#ifndef MC_NODE_H
#define MC_NODE_H

#include <stddef.h>
#include <stdint.h>

#include "filexfer.h"
#include "protocol.h"

typedef struct node node;

typedef struct {
    char name[MC_MAX_NAME + 1];
    char group[16];
    int port;
    char iface[16];          /* 空串 = 自动选择 */
    int ttl;
    int encrypt;
    int retransmit;
    char download_dir[512];  /* 空串 = ~/McastChat */
    int rate_kbps;
} node_config;

void node_config_default(node_config *c);

typedef enum {
    EV_CHAT,     /* id, name, text, self */
    EV_SYSTEM,   /* text */
    EV_MEMBERS,  /* 成员列表有变化，用 node_members() 取快照 */
    EV_ROLE,     /* 管理员身份变化 */
    EV_KEY,      /* 组密钥更新 */
    EV_TRANSFER, /* 文件传输进度/结果 */
    EV_KICKED    /* 本机被删除，name = 管理员昵称 */
} ev_kind;

typedef enum { TS_SENDING, TS_SENT, TS_RECEIVING, TS_DONE, TS_FAILED } transfer_status;

typedef struct {
    ev_kind kind;
    double ts;
    int self;
    char id[2 * MC_ID_LEN + 1];
    char name[MC_MAX_NAME + 1];
    char text[MC_MAX_TEXT + 1];
    /* EV_TRANSFER */
    char fid[2 * MC_ID_LEN + 1];
    int outgoing;
    char fname[256];
    uint64_t size;
    uint32_t done, total;
    int status;
    char reason[160];
    char path[MC_PATH + 300];
} node_event;

typedef void (*node_event_cb)(const node_event *ev, void *user);

typedef struct {
    char id[2 * MC_ID_LEN + 1];
    char name[MC_MAX_NAME + 1];
    char addr[16];
    int admin, has_key, self;
    uint32_t epoch;
} member_info;

node *node_create(const node_config *cfg, node_event_cb cb, void *user);
int node_start(node *n, char *err, size_t errlen);
void node_stop(node *n);
void node_destroy(node *n);

int node_send_chat(node *n, const char *text, char *err, size_t errlen);
int node_send_file(node *n, const char *path, char *err, size_t errlen);
int node_kick(node *n, const char *id_hex, char *err, size_t errlen);

/* 成员快照（第一个是自己），返回个数 */
int node_members(node *n, member_info *out, int max);
int node_is_admin(node *n);
int node_ready(node *n);   /* 加密模式下：是否已持有当前组密钥 */
int node_kicked(node *n);
uint32_t node_epoch(node *n);
void node_stats(node *n, unsigned long *sent, unsigned long *recv, unsigned long *dropped);
const node_config *node_get_config(node *n);
const char *node_download_dir(node *n);
void node_id_hex(node *n, char out[2 * MC_ID_LEN + 1]);

/* 测试用：返回非 0 表示丢弃该数据报（模拟丢包） */
typedef int (*node_drop_hook)(const msg_header *h, void *user);
void node_set_drop_hook(node *n, node_drop_hook hook, void *user);
/* 测试用：直接操作内部状态 */
void node_test_set_kicked(node *n, int kicked);
void node_test_copy_key(node *dst, node *src);
void node_test_send_kick(node *n, const char *target_hex);
void node_test_freeze(node *n); /* 停止发心跳（模拟崩溃） */

#endif
