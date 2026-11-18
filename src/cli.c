/*
 * cli.c —— 命令行界面（无图形环境时使用，也方便远程机器和调试）
 *
 *   直接输入文字        发送聊天消息
 *   /who               查看成员列表
 *   /file <路径>       多播发送文件
 *   /kick <昵称或ID前缀> 删除成员（仅管理员）
 *   /play <文件名>     用系统播放器打开收到的文件
 *   /quit              退出
 */
#include "cli.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "members.h"
#include "node.h"

static pthread_mutex_t out_lk = PTHREAD_MUTEX_INITIALIZER;
static char last_paths[32][MC_PATH + 300];
static int npaths;

static void ts_str(double ts, char out[16])
{
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, 16, "%H:%M:%S", &tm);
}

static void on_event(const node_event *ev, void *user)
{
    (void)user;
    char t[16];
    ts_str(ev->ts, t);
    pthread_mutex_lock(&out_lk);
    switch (ev->kind) {
    case EV_CHAT:
        printf("[%s] %s%s: %s\n", t, ev->name, ev->self ? "(我)" : "", ev->text);
        break;
    case EV_SYSTEM:
        printf("[%s] * %s\n", t, ev->text);
        break;
    case EV_TRANSFER:
        if (ev->status == TS_DONE) {
            printf("[%s] * 收到 %s 的文件 %s（%s）已保存到 %s\n", t, ev->name, ev->fname, ev->reason, ev->path);
            snprintf(last_paths[npaths % 32], sizeof(last_paths[0]), "%s", ev->path);
            npaths++;
        } else if (ev->status == TS_FAILED) {
            printf("[%s] * 文件 %s 传输失败：%s\n", t, ev->fname, ev->reason);
        } else if (ev->status == TS_SENT) {
            printf("[%s] * 文件 %s 已多播发送完毕（%s）\n", t, ev->fname, ev->reason);
        } else if (ev->status == TS_RECEIVING && ev->done == 0 && !ev->reason[0]) {
            printf("[%s] * %s 正在发送文件 %s（%llu 字节）\n", t, ev->name, ev->fname,
                   (unsigned long long)ev->size);
        }
        break;
    case EV_KICKED:
        printf("[%s] * 你已被管理员 %s 移出群组，组密钥已更换，无法再收发消息\n", t, ev->name);
        break;
    default:
        break;
    }
    fflush(stdout);
    pthread_mutex_unlock(&out_lk);
}

static void print_members(node *n)
{
    member_info list[MAX_MEMBERS + 1];
    int cnt = node_members(n, list, MAX_MEMBERS + 1);
    pthread_mutex_lock(&out_lk);
    printf("  当前成员 %d 人：\n", cnt);
    for (int i = 0; i < cnt; i++)
        printf("  %-14s %s  %-15s 密钥版本%-3u %s%s\n", list[i].name, list[i].id, list[i].addr,
               list[i].epoch, list[i].admin ? "★管理员 " : "", list[i].self ? "(我)" : "");
    pthread_mutex_unlock(&out_lk);
}

static void play(const char *key)
{
    for (int i = npaths - 1; i >= 0 && i >= npaths - 32; i--) {
        const char *p = last_paths[i % 32];
        const char *base = strrchr(p, '/');
        if (strstr(base ? base + 1 : p, key)) {
            char cmd[MC_PATH + 400];
            snprintf(cmd, sizeof(cmd), "xdg-open '%s' >/dev/null 2>&1 &", p);
            if (system(cmd) != 0)
                printf("* 无法打开 %s\n", p);
            else
                printf("* 已用系统播放器打开 %s\n", p);
            return;
        }
    }
    printf("* 没有找到收到的文件：%s\n", key);
}

int run_cli(const node_config *cfg)
{
    node *n = node_create(cfg, on_event, NULL);
    if (!n) {
        fprintf(stderr, "创建节点失败（生成 RSA 密钥出错）\n");
        return 1;
    }
    char err[256];
    if (node_start(n, err, sizeof(err)) != 0) {
        fprintf(stderr, "无法加入多播组：%s\n", err);
        node_destroy(n);
        return 1;
    }
    char line[MC_MAX_TEXT + 16];
    while (!node_kicked(n) && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0])
            continue;
        int rc = 0;
        if (strcmp(line, "/quit") == 0) {
            break;
        } else if (strcmp(line, "/who") == 0) {
            print_members(n);
        } else if (strncmp(line, "/file ", 6) == 0) {
            rc = node_send_file(n, line + 6, err, sizeof(err));
        } else if (strncmp(line, "/play ", 6) == 0) {
            play(line + 6);
        } else if (strncmp(line, "/kick ", 6) == 0) {
            const char *key = line + 6;
            member_info list[MAX_MEMBERS + 1];
            int cnt = node_members(n, list, MAX_MEMBERS + 1), hit = -1, hits = 0;
            for (int i = 1; i < cnt; i++)
                if (strcmp(list[i].name, key) == 0 || strncmp(list[i].id, key, strlen(key)) == 0)
                    hit = i, hits++;
            if (hits != 1)
                printf("* 找不到唯一匹配的成员：%s\n", key);
            else
                rc = node_kick(n, list[hit].id, err, sizeof(err));
        } else if (line[0] == '/') {
            printf("* 未知命令。可用：/who /file <路径> /kick <昵称> /play <文件名> /quit\n");
        } else {
            rc = node_send_chat(n, line, err, sizeof(err));
        }
        if (rc != 0)
            printf("* %s\n", err);
        fflush(stdout);
    }
    node_destroy(n);
    return 0;
}
