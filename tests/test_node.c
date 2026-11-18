/* 集成测试：在本机启动多个节点，经真实 UDP 多播通信 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "node.h"

static int failures, checks;
#define CHECK(c)                                                                    \
    do {                                                                            \
        checks++;                                                                   \
        if (!(c)) {                                                                 \
            failures++;                                                             \
            fprintf(stderr, "  失败 %s:%d: %s\n", __FILE__, __LINE__, #c);          \
        }                                                                           \
    } while (0)

/* ---------------- 测试脚手架：记录每个节点收到的事件 ---------------- */

#define MAX_LOG 256
typedef struct {
    pthread_mutex_t lk;
    char chats[MAX_LOG][256];
    int nchat;
    node_event transfers[64];
    int ntrans;
    int kicked;
} event_log;

typedef struct {
    node *n;
    event_log log;
    char name[32];
} peer;

static int base_port;
static char tmpdir[64];

static void on_event(const node_event *ev, void *user)
{
    event_log *l = user;
    pthread_mutex_lock(&l->lk);
    if (ev->kind == EV_CHAT && l->nchat < MAX_LOG)
        snprintf(l->chats[l->nchat++], 256, "%.255s", ev->text);
    else if (ev->kind == EV_TRANSFER && (ev->status == TS_DONE || ev->status == TS_FAILED) && l->ntrans < 64)
        l->transfers[l->ntrans++] = *ev;
    else if (ev->kind == EV_KICKED)
        l->kicked = 1;
    pthread_mutex_unlock(&l->lk);
}

static peer *peer_new(const char *name, int port, int encrypt, int retransmit)
{
    peer *p = calloc(1, sizeof(peer));
    pthread_mutex_init(&p->log.lk, NULL);
    snprintf(p->name, sizeof(p->name), "%s", name);
    node_config c;
    node_config_default(&c);
    snprintf(c.name, sizeof(c.name), "%s", name);
    c.port = port;
    c.encrypt = encrypt;
    c.retransmit = retransmit;
    c.rate_kbps = 4096;
    snprintf(c.download_dir, sizeof(c.download_dir), "%s/dl", tmpdir);
    p->n = node_create(&c, on_event, &p->log);
    char err[256];
    if (node_start(p->n, err, sizeof(err)) != 0) {
        fprintf(stderr, "启动失败：%s\n", err);
        exit(1);
    }
    return p;
}

static void peer_free(peer *p)
{
    node_destroy(p->n);
    pthread_mutex_destroy(&p->log.lk);
    free(p);
}

static int has_chat(peer *p, const char *text)
{
    pthread_mutex_lock(&p->log.lk);
    int found = 0;
    for (int i = 0; i < p->log.nchat; i++)
        found |= strcmp(p->log.chats[i], text) == 0;
    pthread_mutex_unlock(&p->log.lk);
    return found;
}

static int transfer_result(peer *p, node_event *out)
{
    pthread_mutex_lock(&p->log.lk);
    int n = p->log.ntrans;
    if (n && out)
        *out = p->log.transfers[n - 1];
    pthread_mutex_unlock(&p->log.lk);
    return n;
}

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

#define WAIT_UNTIL(cond, secs)                                   \
    ({                                                           \
        double _end = mono() + (secs);                           \
        int _ok = 0;                                             \
        while (mono() < _end) {                                  \
            if (cond) {                                          \
                _ok = 1;                                         \
                break;                                           \
            }                                                    \
            usleep(50000);                                       \
        }                                                        \
        _ok;                                                     \
    })

static int member_count(peer *p)
{
    member_info m[16];
    return node_members(p->n, m, 16) - 1;
}

/* 先启动第一个节点等它成为管理员，再启动其余节点，等所有人拿到密钥 */
static int form_group(peer **ps, const char **names, int cnt, int port, int enc, int retr)
{
    ps[0] = peer_new(names[0], port, enc, retr);
    if (!WAIT_UNTIL(node_is_admin(ps[0]->n), 5))
        return 0;
    for (int i = 1; i < cnt; i++)
        ps[i] = peer_new(names[i], port, enc, retr);
    return WAIT_UNTIL(({
                          int all = 1;
                          for (int i = 0; i < cnt; i++)
                              all &= node_ready(ps[i]->n) && member_count(ps[i]) == cnt - 1;
                          all;
                      }),
                      10);
}

static void free_all(peer **ps, int cnt)
{
    for (int i = 0; i < cnt; i++)
        if (ps[i])
            peer_free(ps[i]);
}

static const char *ABC[] = {"alice", "bob", "carol"};

static void make_file(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    uint8_t *b = malloc(size);
    random_bytes(b, size);
    fwrite(b, 1, size, f);
    fclose(f);
    free(b);
}

static int same_file(const char *a, const char *b)
{
    uint8_t x[32], y[32];
    return sha256_file(a, x) == 0 && sha256_file(b, y) == 0 && memcmp(x, y, 32) == 0;
}

/* ---------------- 测试用例 ---------------- */

static void test_election_and_keys(int port)
{
    peer *p[3] = {0};
    CHECK(form_group(p, ABC, 3, port, 1, 0));
    CHECK(node_is_admin(p[0]->n) && !node_is_admin(p[1]->n) && !node_is_admin(p[2]->n));
    CHECK(node_epoch(p[0]->n) == 1 && node_epoch(p[1]->n) == 1 && node_epoch(p[2]->n) == 1);
    free_all(p, 3);
}

static void test_chat_one_to_many(int port)
{
    peer *p[3] = {0};
    char err[128];
    CHECK(form_group(p, ABC, 3, port, 1, 0));
    CHECK(node_send_chat(p[0]->n, "你好，多播！", err, sizeof(err)) == 0);
    CHECK(WAIT_UNTIL(has_chat(p[1], "你好，多播！") && has_chat(p[2], "你好，多播！"), 5));
    free_all(p, 3);
}

static void test_file_transfer(int port)
{
    peer *p[3] = {0};
    char err[128], src[128];
    CHECK(form_group(p, ABC, 3, port, 1, 0));
    snprintf(src, sizeof(src), "%s/clip.mp3", tmpdir);
    make_file(src, 800000);
    CHECK(node_send_file(p[0]->n, src, err, sizeof(err)) == 0);
    node_event ev;
    for (int i = 1; i < 3; i++) {
        CHECK(WAIT_UNTIL(transfer_result(p[i], &ev), 15));
        CHECK(ev.status == TS_DONE && same_file(src, ev.path));
    }
    free_all(p, 3);
}

static void test_kick(int port)
{
    peer *p[3] = {0};
    char err[128], cid[17];
    CHECK(form_group(p, ABC, 3, port, 1, 0));
    uint32_t old = node_epoch(p[0]->n);
    node_id_hex(p[2]->n, cid);
    CHECK(node_kick(p[0]->n, cid, err, sizeof(err)) == 0);
    CHECK(WAIT_UNTIL(p[2]->log.kicked && node_kicked(p[2]->n), 5));
    CHECK(WAIT_UNTIL(node_epoch(p[1]->n) == old + 1 && node_epoch(p[0]->n) == old + 1, 5));
    CHECK(member_count(p[1]) == 1);
    /* 模拟"被踢者不肯退出"：恢复其接收逻辑，看它能否解密新消息 */
    node_test_set_kicked(p[2]->n, 0);
    CHECK(node_send_chat(p[0]->n, "被踢之后的消息", err, sizeof(err)) == 0);
    CHECK(WAIT_UNTIL(has_chat(p[1], "被踢之后的消息"), 5));
    usleep(500000);
    CHECK(!has_chat(p[2], "被踢之后的消息"));
    /* 即使被踢者设法拿到了新密钥，它发来的消息也会因黑名单被拒收 */
    node_test_copy_key(p[2]->n, p[1]->n);
    CHECK(node_send_chat(p[2]->n, "我还在", err, sizeof(err)) == 0);
    usleep(500000);
    CHECK(!has_chat(p[1], "我还在"));
    free_all(p, 3);
}

static void test_admin_handover(int port)
{
    peer *p[3] = {0};
    char err[128];
    CHECK(form_group(p, ABC, 3, port, 1, 0));
    peer_free(p[0]);
    p[0] = NULL;
    CHECK(WAIT_UNTIL(node_is_admin(p[1]->n), 5)); /* bob 上线比 carol 早 */
    CHECK(WAIT_UNTIL(node_ready(p[2]->n) && node_epoch(p[2]->n) == node_epoch(p[1]->n), 5));
    CHECK(!node_is_admin(p[2]->n));
    CHECK(node_send_chat(p[1]->n, "新管理员上任", err, sizeof(err)) == 0);
    CHECK(WAIT_UNTIL(has_chat(p[2], "新管理员上任"), 5));
    free_all(p, 3);
}

static void test_timeout(int port)
{
    peer *p[2] = {0};
    CHECK(form_group(p, ABC, 2, port, 1, 0));
    node_test_freeze(p[1]->n); /* 模拟崩溃：不再发心跳，也不发 BYE */
    CHECK(WAIT_UNTIL(member_count(p[0]) == 0, 10));
    free_all(p, 2);
}

static void test_simultaneous_start(int port)
{
    peer *p[3];
    for (int i = 0; i < 3; i++)
        p[i] = peer_new(ABC[i], port, 1, 0);
    CHECK(WAIT_UNTIL(({
                         int admins = 0, ready = 1;
                         for (int i = 0; i < 3; i++) {
                             admins += node_is_admin(p[i]->n);
                             ready &= node_ready(p[i]->n);
                         }
                         admins == 1 && ready && node_epoch(p[0]->n) == node_epoch(p[1]->n) &&
                             node_epoch(p[1]->n) == node_epoch(p[2]->n);
                     }),
                     10));
    CHECK(node_is_admin(p[0]->n)); /* 最早启动者 */
    free_all(p, 3);
}

static void test_plaintext(int port)
{
    peer *p[2] = {0};
    char err[128];
    CHECK(form_group(p, ABC, 2, port, 0, 0));
    CHECK(node_send_chat(p[0]->n, "明文消息", err, sizeof(err)) == 0);
    CHECK(WAIT_UNTIL(has_chat(p[1], "明文消息"), 5));
    CHECK(node_epoch(p[0]->n) == 0 && node_epoch(p[1]->n) == 0);
    free_all(p, 2);
}

/* 丢包模拟：丢弃首次到达的部分文件分片 */
typedef struct {
    pthread_mutex_t lk;
    unsigned seen[4096];
    int nseen;
    int mode;   /* 0 = 按概率丢；1 = 只丢第 5 个分片 */
    int count;
    unsigned rng;
} dropper;

static int drop_hook(const msg_header *h, void *user)
{
    dropper *d = user;
    if (h->type != MT_FILE_CHUNK)
        return 0;
    pthread_mutex_lock(&d->lk);
    int drop = 0;
    if (d->mode == 1) {
        drop = ++d->count == 5;
    } else {
        int seen = 0;
        for (int i = 0; i < d->nseen; i++)
            seen |= d->seen[i] == h->seq;
        if (!seen && d->nseen < 4096) {
            d->seen[d->nseen++] = h->seq;
            d->rng = d->rng * 1103515245u + 12345u;
            drop = (d->rng >> 16) % 100 < 20; /* 20% */
        }
    }
    pthread_mutex_unlock(&d->lk);
    return drop;
}

static void test_retransmit(int port)
{
    peer *p[2] = {0};
    char err[128], src[128];
    CHECK(form_group(p, ABC, 2, port, 1, 1));
    static dropper d;
    memset(&d, 0, sizeof(d));
    pthread_mutex_init(&d.lk, NULL);
    d.rng = 1;
    node_set_drop_hook(p[1]->n, drop_hook, &d);
    snprintf(src, sizeof(src), "%s/video.mp4", tmpdir);
    make_file(src, 600000);
    CHECK(node_send_file(p[0]->n, src, err, sizeof(err)) == 0);
    node_event ev;
    CHECK(WAIT_UNTIL(transfer_result(p[1], &ev), 25));
    CHECK(ev.status == TS_DONE && same_file(src, ev.path));
    printf("    模拟丢弃了约 20%% 的分片，补发后接收成功\n");
    node_set_drop_hook(p[1]->n, NULL, NULL);
    free_all(p, 2);
}

static void test_loss_without_retransmit(int port)
{
    peer *p[2] = {0};
    char err[128], src[128];
    CHECK(form_group(p, ABC, 2, port, 1, 0));
    static dropper d;
    memset(&d, 0, sizeof(d));
    pthread_mutex_init(&d.lk, NULL);
    d.mode = 1;
    node_set_drop_hook(p[1]->n, drop_hook, &d);
    snprintf(src, sizeof(src), "%s/a.bin", tmpdir);
    make_file(src, 50000);
    CHECK(node_send_file(p[0]->n, src, err, sizeof(err)) == 0);
    node_event ev;
    CHECK(WAIT_UNTIL(transfer_result(p[1], &ev), 10));
    CHECK(ev.status == TS_FAILED && strstr(ev.reason, "丢失 1 个分片"));
    node_set_drop_hook(p[1]->n, NULL, NULL);
    free_all(p, 2);
}

static void test_forged_kick(int port)
{
    peer *p[3] = {0};
    char bid[17];
    CHECK(form_group(p, ABC, 3, port, 1, 0));
    node_id_hex(p[1]->n, bid);
    node_test_send_kick(p[2]->n, bid); /* 普通成员 carol 伪造踢人报文 */
    usleep(800000);
    CHECK(!node_kicked(p[1]->n) && member_count(p[1]) == 2);
    free_all(p, 3);
}

static void test_non_admin_cannot_kick(int port)
{
    peer *p[2] = {0};
    char err[128], aid[17];
    CHECK(form_group(p, ABC, 2, port, 1, 0));
    node_id_hex(p[0]->n, aid);
    CHECK(node_kick(p[1]->n, aid, err, sizeof(err)) != 0 && strstr(err, "管理员"));
    free_all(p, 2);
}

typedef void (*test_fn)(int port);
static const struct {
    const char *name;
    test_fn fn;
} TESTS[] = {
    {"管理员选举与密钥分发", test_election_and_keys},
    {"1-N 文本聊天", test_chat_one_to_many},
    {"文件多播传输与 SHA-256 校验", test_file_transfer},
    {"删除成员：换钥、被删者无法解密、其消息被拒收", test_kick},
    {"管理员离开后自动接任", test_admin_handover},
    {"成员超时判定", test_timeout},
    {"同时启动只保留一个管理员", test_simultaneous_start},
    {"明文模式", test_plaintext},
    {"20% 随机丢包下重传恢复", test_retransmit},
    {"不开重传时丢包被正确报告", test_loss_without_retransmit},
    {"伪造的踢人报文被忽略", test_forged_kick},
    {"普通成员不能删除他人", test_non_admin_cannot_kick},
};

int main(int argc, char **argv)
{
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/mc_node_XXXXXX");
    if (!mkdtemp(tmpdir))
        return 1;
    base_port = 51000 + (int)(getpid() % 500) * 20;
    printf("== 多节点集成测试（本机 UDP 多播，端口从 %d 起）\n", base_port);
    int n = (int)(sizeof(TESTS) / sizeof(TESTS[0]));
    for (int i = 0; i < n; i++) {
        if (argc > 1 && !strstr(TESTS[i].name, argv[1]))
            continue;
        int before = failures;
        double t0 = mono();
        TESTS[i].fn(base_port + i);
        printf("- [%s] %s（%.1f 秒）\n", failures == before ? "通过" : "失败", TESTS[i].name, mono() - t0);
    }
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    if (system(cmd) != 0)
        return 1;
    printf("集成测试：%d 项检查，%d 项失败\n", checks, failures);
    return failures ? 1 : 0;
}
