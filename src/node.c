/*
 * node.c —— 节点协议逻辑实现
 *
 * 线程：
 *   recv  线程：阻塞 recvfrom，解析并处理每个数据报；
 *   timer 线程：每 0.25 秒发心跳、判定超时、选举、清理旧密钥、检查文件完整性；
 *   每个文件发送 / 补发各开一个工作线程。
 * 所有共享状态由一把递归互斥锁 lk 保护。
 */
#include "node.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "members.h"
#include "net.h"

#define DISCOVERY_TIME 2.0
#define KEY_RESEND_INTERVAL 1.0
#define OLD_KEY_GRACE 10.0
#define KICK_RESEND_INTERVAL 3.0
#define DEPARTED_IGNORE 5.0
#define TICK_US 250000
#define MAX_KEYS 4
#define MAX_NACK_RANGES 150

enum { F_ADMIN = 1, F_HAS_KEY = 2, F_ENC = 4 };

typedef struct {
    int used;
    uint32_t epoch;
    uint8_t key[MC_KEY_LEN];
    double expiry; /* 0 = 不过期 */
} group_key;

typedef struct {
    uint8_t id[MC_ID_LEN];
    double t;
} id_time;

struct node {
    node_config cfg;
    node_event_cb cb;
    void *user;
    identity idn;
    double since;
    char dl_dir[MC_PATH];

    pthread_mutex_t lk;
    member_table mt;
    int is_admin;
    int has_admin;
    uint8_t admin_id[MC_ID_LEN];
    int discovering;
    double discovery_deadline;
    int kicked;
    int frozen;

    group_key keys[MAX_KEYS];
    uint32_t epoch;
    int drop_old_flag;

    outgoing_file out[MAX_OUTGOING];
    incoming_file in[MAX_INCOMING];

    uint32_t seq;
    double next_heartbeat;
    double undecryptable_warned;
    id_time departed[16];
    int departed_pos;
    id_time kick_sent[16];
    uint8_t warned[32][MC_ID_LEN];
    int nwarned;
    id_time meta_req[16];

    int fd;
    volatile int running;
    int active_workers;
    pthread_t th_recv, th_timer;
    unsigned long st_sent, st_recv, st_dropped;

    node_drop_hook drop_hook;
    void *drop_user;
};

/* ======================================================== 工具 */

static double now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static double now_wall(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static void lock(node *n) { pthread_mutex_lock(&n->lk); }
static void unlock(node *n) { pthread_mutex_unlock(&n->lk); }

static int id_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, MC_ID_LEN) == 0; }

static void emit(node *n, node_event *ev)
{
    if (!ev->ts)
        ev->ts = now_wall();
    if (n->cb)
        n->cb(ev, n->user);
}

static void sys_msg(node *n, const char *fmt, ...)
{
    node_event ev = {.kind = EV_SYSTEM};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ev.text, sizeof(ev.text), fmt, ap);
    va_end(ap);
    emit(n, &ev);
}

static void emit_simple(node *n, ev_kind k)
{
    node_event ev = {.kind = k};
    emit(n, &ev);
}

static void emit_in(node *n, incoming_file *f, int status, const char *reason)
{
    node_event ev = {.kind = EV_TRANSFER, .outgoing = 0, .size = f->size, .done = f->received,
                     .total = f->chunks, .status = status};
    id_to_hex(f->fid, ev.fid);
    snprintf(ev.fname, sizeof(ev.fname), "%s", f->name);
    snprintf(ev.name, sizeof(ev.name), "%s", f->sender_name);
    snprintf(ev.reason, sizeof(ev.reason), "%s", reason ? reason : "");
    if (f->state == IN_DONE)
        snprintf(ev.path, sizeof(ev.path), "%s", f->final_path);
    emit(n, &ev);
}

static void emit_out(node *n, outgoing_file *o, uint32_t done, int status, const char *reason)
{
    node_event ev = {.kind = EV_TRANSFER, .outgoing = 1, .size = o->size, .done = done,
                     .total = o->chunks, .status = status, .self = 1};
    id_to_hex(o->fid, ev.fid);
    snprintf(ev.fname, sizeof(ev.fname), "%s", o->name);
    snprintf(ev.name, sizeof(ev.name), "%s", n->cfg.name);
    snprintf(ev.reason, sizeof(ev.reason), "%s", reason ? reason : "");
    snprintf(ev.path, sizeof(ev.path), "%s", o->path);
    emit(n, &ev);
}

static group_key *key_for(node *n, uint32_t epoch)
{
    for (int i = 0; i < MAX_KEYS; i++)
        if (n->keys[i].used && n->keys[i].epoch == epoch)
            return &n->keys[i];
    return NULL;
}

static int is_ready(node *n) { return !n->cfg.encrypt || key_for(n, n->epoch) != NULL; }

static void clear_keys(node *n) { memset(n->keys, 0, sizeof(n->keys)); }

/* 旧密钥再保留 OLD_KEY_GRACE 秒，便于解密在途数据 */
static void age_keys(node *n)
{
    for (int i = 0; i < MAX_KEYS; i++)
        if (n->keys[i].used && n->keys[i].expiry == 0)
            n->keys[i].expiry = now_mono() + OLD_KEY_GRACE;
}

static void install_key(node *n, uint32_t epoch, const uint8_t key[MC_KEY_LEN])
{
    group_key *slot = key_for(n, epoch);
    for (int i = 0; !slot && i < MAX_KEYS; i++)
        if (!n->keys[i].used)
            slot = &n->keys[i];
    if (!slot) { /* 满了：淘汰最早过期的 */
        slot = &n->keys[0];
        for (int i = 1; i < MAX_KEYS; i++)
            if (n->keys[i].expiry < slot->expiry)
                slot = &n->keys[i];
    }
    slot->used = 1;
    slot->epoch = epoch;
    slot->expiry = 0;
    memcpy(slot->key, key, MC_KEY_LEN);
    n->epoch = epoch;
}

/* ======================================================== 发送 */

static int send_raw(node *n, int type, const uint8_t *payload, size_t len, uint32_t epoch)
{
    uint8_t buf[MC_MAX_DATAGRAM];
    if (len + MC_HEADER_SIZE > sizeof(buf) || n->fd < 0)
        return -1;
    msg_header h = {.type = (uint8_t)type, .epoch = epoch};
    memcpy(h.sender, n->idn.id, MC_ID_LEN);
    lock(n);
    h.seq = ++n->seq;
    unlock(n);
    hdr_pack(&h, buf);
    if (len)
        memcpy(buf + MC_HEADER_SIZE, payload, len);
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons((uint16_t)n->cfg.port)};
    inet_pton(AF_INET, n->cfg.group, &dst.sin_addr);
    ssize_t r = sendto(n->fd, buf, len + MC_HEADER_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (r < 0)
        return -1;
    __atomic_add_fetch(&n->st_sent, 1, __ATOMIC_RELAXED);
    return 0;
}

/* 加密模式下用当前组密钥 AES-GCM 加密后发送，头部作为 AAD */
static int send_secure(node *n, int type, const uint8_t *pt, size_t len)
{
    if (!n->cfg.encrypt)
        return send_raw(n, type, pt, len, 0);
    uint8_t key[MC_KEY_LEN];
    uint32_t epoch;
    lock(n);
    group_key *k = key_for(n, n->epoch);
    if (k) {
        memcpy(key, k->key, MC_KEY_LEN);
        epoch = n->epoch;
    }
    unlock(n);
    if (!k)
        return -1;

    static __thread uint8_t buf[MC_MAX_DATAGRAM];
    if (MC_HEADER_SIZE + len + MC_GCM_OVERHEAD > sizeof(buf))
        return -1;
    msg_header h = {.type = (uint8_t)type, .epoch = epoch};
    memcpy(h.sender, n->idn.id, MC_ID_LEN);
    lock(n);
    h.seq = ++n->seq;
    unlock(n);
    hdr_pack(&h, buf);
    int clen = gcm_seal(key, pt, len, buf, MC_HEADER_SIZE, buf + MC_HEADER_SIZE);
    if (clen < 0)
        return -1;
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons((uint16_t)n->cfg.port)};
    inet_pton(AF_INET, n->cfg.group, &dst.sin_addr);
    if (sendto(n->fd, buf, MC_HEADER_SIZE + (size_t)clen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        return -1;
    __atomic_add_fetch(&n->st_sent, 1, __ATOMIC_RELAXED);
    return 0;
}

static void send_presence(node *n, int type)
{
    uint8_t buf[1024];
    wbuf w;
    wb_init(&w, buf, sizeof(buf));
    lock(n);
    uint8_t flags = (n->is_admin ? F_ADMIN : 0) | (is_ready(n) ? F_HAS_KEY : 0) |
                    (n->cfg.encrypt ? F_ENC : 0);
    wb_u64(&w, (uint64_t)(n->since * 1000.0));
    wb_u8(&w, flags);
    wb_u32(&w, n->epoch);
    wb_str16(&w, n->cfg.name);
    wb_u16(&w, (uint16_t)n->idn.pub_len);
    wb_bytes(&w, n->idn.pub_der, (size_t)n->idn.pub_len);
    unlock(n);
    if (!w.err)
        send_raw(n, type, buf, w.len, 0);
}

/* 签名报文格式：u16 正文长度 + 正文 + u16 签名长度 + 签名 */
static int send_signed(node *n, int type, const uint8_t *body, size_t blen)
{
    uint8_t sig[MC_RSA_BYTES], buf[1024];
    size_t slen;
    if (rsa_sign(&n->idn, body, blen, sig, &slen) != 0)
        return -1;
    wbuf w;
    wb_init(&w, buf, sizeof(buf));
    wb_u16(&w, (uint16_t)blen);
    wb_bytes(&w, body, blen);
    wb_u16(&w, (uint16_t)slen);
    wb_bytes(&w, sig, slen);
    return w.err ? -1 : send_raw(n, type, buf, w.len, 0);
}

/* ======================================================== 成员与管理员 */

static void update_admin_id(node *n)
{
    uint8_t new_id[MC_ID_LEN];
    int has = 0;
    if (n->is_admin) {
        memcpy(new_id, n->idn.id, MC_ID_LEN);
        has = 1;
    } else {
        member *a = mt_first_admin(&n->mt);
        if (a) {
            memcpy(new_id, a->id, MC_ID_LEN);
            has = 1;
        }
    }
    int changed = has != n->has_admin || (has && !id_eq(new_id, n->admin_id));
    n->has_admin = has;
    if (has)
        memcpy(n->admin_id, new_id, MC_ID_LEN);
    if (changed) {
        emit_simple(n, EV_ROLE);
        emit_simple(n, EV_MEMBERS);
    }
}

static void send_key_to(node *n, member *m);
static void rotate_key(node *n, int drop_old);

static void become_admin(node *n)
{
    n->is_admin = 1;
    n->has_admin = 1;
    memcpy(n->admin_id, n->idn.id, MC_ID_LEN);
    n->discovering = 0;
    emit_simple(n, EV_ROLE);
    if (n->cfg.encrypt) {
        sys_msg(n, "本机成为管理员，生成新的组密钥");
        rotate_key(n, 0);
    } else {
        sys_msg(n, "本机成为管理员");
        send_presence(n, MT_HEARTBEAT);
        emit_simple(n, EV_MEMBERS);
    }
}

/* 管理员缺位时，(上线时间, ID) 最小者接任。只有选中自己时才行动 */
static void elect(node *n)
{
    if (n->is_admin || n->has_admin || n->kicked)
        return;
    double best_since = n->since;
    const uint8_t *best = n->idn.id;
    for (int i = 0; i < MAX_MEMBERS; i++) {
        member *m = &n->mt.m[i];
        if (m->used && rank_cmp(m->since, m->id, best_since, best) < 0) {
            best_since = m->since;
            best = m->id;
        }
    }
    if (best == n->idn.id)
        become_admin(n);
}

static void member_gone(node *n, const uint8_t id[MC_ID_LEN])
{
    emit_simple(n, EV_MEMBERS);
    if (n->has_admin && id_eq(id, n->admin_id) && !n->is_admin) {
        n->has_admin = 0;
        sys_msg(n, "管理员已离开，正在选举新管理员");
        elect(n);
    } else if (n->is_admin && n->cfg.encrypt && mt_count(&n->mt) > 0) {
        /* 有人离开后更换密钥：离开者无法再解密之后的消息 */
        rotate_key(n, 0);
    }
}

static void warn_once(node *n, const uint8_t id[MC_ID_LEN], const char *text)
{
    for (int i = 0; i < n->nwarned; i++)
        if (id_eq(n->warned[i], id))
            return;
    if (n->nwarned < 32)
        memcpy(n->warned[n->nwarned++], id, MC_ID_LEN);
    sys_msg(n, "%s", text);
}

static int recently_departed(node *n, const uint8_t id[MC_ID_LEN])
{
    double t = now_mono();
    for (int i = 0; i < 16; i++)
        if (n->departed[i].t > 0 && id_eq(n->departed[i].id, id) && t - n->departed[i].t < DEPARTED_IGNORE)
            return 1;
    return 0;
}

static void send_kick(node *n, const uint8_t target[MC_ID_LEN], int rate_limited)
{
    double t = now_mono();
    id_time *slot = NULL, *oldest = &n->kick_sent[0];
    for (int i = 0; i < 16; i++) {
        if (id_eq(n->kick_sent[i].id, target))
            slot = &n->kick_sent[i];
        if (n->kick_sent[i].t < oldest->t)
            oldest = &n->kick_sent[i];
    }
    if (slot && rate_limited && t - slot->t < KICK_RESEND_INTERVAL)
        return;
    if (!slot) {
        slot = oldest;
        memcpy(slot->id, target, MC_ID_LEN);
    }
    slot->t = t;
    uint8_t body[64];
    wbuf w;
    wb_init(&w, body, sizeof(body));
    wb_bytes(&w, target, MC_ID_LEN);
    wb_u64(&w, (uint64_t)(now_wall() * 1000));
    send_signed(n, MT_KICK, body, w.len);
}

static void on_admin_claim(node *n, member *other)
{
    n->discovering = 0;
    if (!n->is_admin)
        return;
    if (rank_cmp(other->since, other->id, n->since, n->idn.id) < 0) {
        /* 对方更早，自己让位 */
        n->is_admin = 0;
        memcpy(n->admin_id, other->id, MC_ID_LEN);
        n->has_admin = 1;
        if (n->cfg.encrypt) {
            clear_keys(n);
            n->epoch = 0;
        }
        sys_msg(n, "发现更早的管理员 %s，本机转为普通成员，等待其分发密钥", other->name);
        send_presence(n, MT_HEARTBEAT);
        emit_simple(n, EV_ROLE);
        emit_simple(n, EV_MEMBERS);
    } else {
        send_presence(n, MT_HEARTBEAT); /* 让对方尽快看到自己的管理员心跳 */
    }
}

static void on_presence(node *n, const msg_header *h, const uint8_t *p, size_t len, const char *addr)
{
    rbuf r;
    rb_init(&r, p, len);
    double since = (double)rb_u64(&r) / 1000.0;
    uint8_t flags = rb_u8(&r);
    uint32_t epoch = rb_u32(&r);
    char name[MC_MAX_NAME + 1];
    rb_str16(&r, name, sizeof(name));
    uint16_t publen = rb_u16(&r);
    const uint8_t *pub = rb_bytes(&r, publen);
    if (r.err || publen > MC_PUB_MAX)
        return;
    uint8_t idc[MC_ID_LEN];
    node_id_of(pub, publen, idc);
    if (!id_eq(idc, h->sender))
        return; /* 节点 ID 必须是公钥的哈希，防止冒用他人 ID */

    if (recently_departed(n, h->sender))
        return; /* 刚发过 BYE 的节点，忽略迟到的心跳 */
    if (mt_is_banned(&n->mt, h->sender)) {
        /* 被删除的成员仍在发心跳：管理员定期重发 KICK，其他人忽略 */
        if (n->is_admin)
            send_kick(n, h->sender, 1);
        return;
    }
    if (!!(flags & F_ENC) != !!n->cfg.encrypt) {
        char t[128];
        snprintf(t, sizeof(t), "%s 的加密设置与本机不同，已忽略该成员", name);
        warn_once(n, h->sender, t);
        return;
    }

    int is_new = 0, changed = 0;
    member *m = mt_find(&n->mt, h->sender);
    if (!m) {
        m = mt_add(&n->mt, h->sender);
        if (!m)
            return;
        m->pub = pubkey_load(pub, publen);
        if (!m->pub) {
            mt_remove(m);
            return;
        }
        m->since = since;
        is_new = 1;
    }
    snprintf(m->name, sizeof(m->name), "%s", name);
    snprintf(m->addr, sizeof(m->addr), "%s", addr);
    m->last_seen = now_mono();
    int adm = !!(flags & F_ADMIN), hk = !!(flags & F_HAS_KEY);
    changed = m->is_admin != adm || m->epoch != epoch || m->has_key != hk;
    m->is_admin = adm;
    m->epoch = epoch;
    m->has_key = hk;

    if (is_new)
        sys_msg(n, "%s 加入了群组（%s）", m->name, addr);
    if (h->type == MT_HELLO)
        send_presence(n, MT_HEARTBEAT); /* 新成员上线：立即回一次心跳 */

    if (m->is_admin) {
        on_admin_claim(n, m);
    } else if (n->has_admin && !n->is_admin && id_eq(n->admin_id, m->id)) {
        n->has_admin = 0; /* 原管理员让位了 */
        changed = 1;
    }
    update_admin_id(n);

    if (n->is_admin && n->cfg.encrypt && (!m->has_key || m->epoch != n->epoch))
        send_key_to(n, m);
    if (is_new || changed)
        emit_simple(n, EV_MEMBERS);
}

static void on_bye(node *n, const uint8_t id[MC_ID_LEN])
{
    member *m = mt_find(&n->mt, id);
    memcpy(n->departed[n->departed_pos].id, id, MC_ID_LEN);
    n->departed[n->departed_pos].t = now_mono();
    n->departed_pos = (n->departed_pos + 1) % 16;
    if (!m)
        return;
    sys_msg(n, "%s 离开了群组", m->name);
    uint8_t gone[MC_ID_LEN];
    memcpy(gone, id, MC_ID_LEN);
    mt_remove(m);
    member_gone(n, gone);
}

/* ======================================================== 密钥管理 */

static void rotate_key(node *n, int drop_old)
{
    uint32_t mx = n->epoch;
    for (int i = 0; i < MAX_MEMBERS; i++)
        if (n->mt.m[i].used && n->mt.m[i].epoch > mx)
            mx = n->mt.m[i].epoch;
    uint8_t key[MC_KEY_LEN];
    random_bytes(key, MC_KEY_LEN);
    if (drop_old)
        clear_keys(n);
    else
        age_keys(n);
    install_key(n, mx + 1, key);
    n->drop_old_flag = drop_old;
    for (int i = 0; i < MAX_MEMBERS; i++)
        n->mt.m[i].last_key_sent = 0;
    send_presence(n, MT_HEARTBEAT);
    for (int i = 0; i < MAX_MEMBERS; i++)
        if (n->mt.m[i].used)
            send_key_to(n, &n->mt.m[i]);
    emit_simple(n, EV_KEY);
    emit_simple(n, EV_MEMBERS);
}

/* KEY_DIST 正文：目标ID(8) + 版本(4) + drop_old(1) + u16 长度 + RSA-OAEP(组密钥) + 时间戳(8) */
static void send_key_to(node *n, member *m)
{
    double t = now_mono();
    group_key *k = key_for(n, n->epoch);
    if (!n->is_admin || !k || t - m->last_key_sent < KEY_RESEND_INTERVAL)
        return;
    m->last_key_sent = t;
    uint8_t enc[MC_RSA_BYTES], body[512];
    size_t elen;
    if (rsa_wrap(m->pub, k->key, enc, &elen) != 0)
        return;
    wbuf w;
    wb_init(&w, body, sizeof(body));
    wb_bytes(&w, m->id, MC_ID_LEN);
    wb_u32(&w, n->epoch);
    wb_u8(&w, (uint8_t)n->drop_old_flag);
    wb_u16(&w, (uint16_t)elen);
    wb_bytes(&w, enc, elen);
    wb_u64(&w, (uint64_t)(now_wall() * 1000));
    send_signed(n, MT_KEY_DIST, body, w.len);
}

/* 校验来自当前管理员的签名报文，成功返回正文指针 */
static const uint8_t *verify_admin_msg(node *n, const uint8_t *sender, const uint8_t *p, size_t len,
                                       size_t *blen, member **who)
{
    rbuf r;
    rb_init(&r, p, len);
    uint16_t bl = rb_u16(&r);
    const uint8_t *body = rb_bytes(&r, bl);
    uint16_t sl = rb_u16(&r);
    const uint8_t *sig = rb_bytes(&r, sl);
    if (r.err)
        return NULL;
    member *m = mt_find(&n->mt, sender);
    int trusted = m && ((n->has_admin && id_eq(sender, n->admin_id)) || (!n->has_admin && m->is_admin));
    if (!trusted)
        return NULL;
    if (!rsa_verify(m->pub, body, bl, sig, sl)) {
        sys_msg(n, "收到 %s 的签名无效的管理报文，已丢弃", m->name);
        return NULL;
    }
    *blen = bl;
    *who = m;
    return body;
}

static void on_key_dist(node *n, const uint8_t *sender, const uint8_t *p, size_t len)
{
    if (!n->cfg.encrypt)
        return;
    size_t blen;
    member *adm;
    const uint8_t *body = verify_admin_msg(n, sender, p, len, &blen, &adm);
    if (!body)
        return;
    rbuf r;
    rb_init(&r, body, blen);
    const uint8_t *target = rb_bytes(&r, MC_ID_LEN);
    uint8_t tgt[MC_ID_LEN];
    memcpy(tgt, target, MC_ID_LEN);
    uint32_t epoch = rb_u32(&r);
    uint8_t drop_old = rb_u8(&r);
    uint16_t elen = rb_u16(&r);
    const uint8_t *enc = rb_bytes(&r, elen);
    if (r.err || !id_eq(tgt, n->idn.id))
        return;
    uint8_t key[MC_KEY_LEN];
    if (rsa_unwrap(&n->idn, enc, elen, key) != 0)
        return;
    if (n->epoch == epoch && key_for(n, epoch))
        return;
    if (drop_old)
        clear_keys(n);
    else
        age_keys(n);
    install_key(n, epoch, key);
    memcpy(n->admin_id, sender, MC_ID_LEN);
    n->has_admin = 1;
    n->discovering = 0;
    sys_msg(n, "已从管理员处获得组密钥（版本 %u）", epoch);
    send_presence(n, MT_HEARTBEAT);
    emit_simple(n, EV_KEY);
    emit_simple(n, EV_MEMBERS);
}

static void on_kick(node *n, const uint8_t *sender, const uint8_t *p, size_t len)
{
    size_t blen;
    member *adm;
    const uint8_t *body = verify_admin_msg(n, sender, p, len, &blen, &adm);
    if (!body || blen < MC_ID_LEN)
        return;
    uint8_t target[MC_ID_LEN];
    memcpy(target, body, MC_ID_LEN);
    if (id_eq(target, n->idn.id)) {
        n->kicked = 1;
        clear_keys(n);
        n->epoch = 0;
        node_event ev = {.kind = EV_KICKED};
        snprintf(ev.name, sizeof(ev.name), "%s", adm->name);
        emit(n, &ev);
        return;
    }
    mt_ban(&n->mt, target);
    member *m = mt_find(&n->mt, target);
    if (m) {
        sys_msg(n, "%s 将 %s 移出了群组", adm->name, m->name);
        mt_remove(m);
        emit_simple(n, EV_MEMBERS);
    }
}

/* ======================================================== 文件发送 */

typedef struct {
    node *n;
    outgoing_file *o;
} worker_arg;

static void rate_wait(node *n, double start, uint64_t sent_bytes)
{
    double rate = (double)n->cfg.rate_kbps * 1024.0;
    double ahead = (double)sent_bytes / rate - (now_mono() - start);
    if (ahead > 0.002)
        usleep((useconds_t)(ahead * 1e6));
}

static void pack_meta(outgoing_file *o, wbuf *w)
{
    wb_bytes(w, o->fid, MC_ID_LEN);
    wb_u64(w, o->size);
    wb_u32(w, o->chunks);
    wb_bytes(w, o->sha, 32);
    wb_str16(w, o->name);
}

static int send_chunk(node *n, outgoing_file *o, uint32_t idx)
{
    uint8_t buf[MC_ID_LEN + 4 + MC_CHUNK_DATA];
    wbuf w;
    wb_init(&w, buf, sizeof(buf));
    wb_bytes(&w, o->fid, MC_ID_LEN);
    wb_u32(&w, idx);
    ssize_t r = outgoing_read(o, idx, buf + w.len);
    if (r < 0)
        return -1;
    return send_secure(n, MT_FILE_CHUNK, buf, w.len + (size_t)r);
}

static void send_end(node *n, outgoing_file *o)
{
    uint8_t buf[16];
    wbuf w;
    wb_init(&w, buf, sizeof(buf));
    wb_bytes(&w, o->fid, MC_ID_LEN);
    wb_u32(&w, o->chunks);
    send_secure(n, MT_FILE_END, buf, w.len);
}

static void *send_file_worker(void *arg)
{
    worker_arg *a = arg;
    node *n = a->n;
    outgoing_file *o = a->o;
    free(a);
    const char *fail = NULL;

    emit_out(n, o, 0, TS_SENDING, "计算 SHA-256…");
    if (sha256_file(o->path, o->sha) != 0) {
        fail = "读取文件失败";
        goto done;
    }
    uint8_t meta[512];
    wbuf w;
    wb_init(&w, meta, sizeof(meta));
    pack_meta(o, &w);
    /* 元信息很关键，发两次 */
    if (send_secure(n, MT_FILE_META, meta, w.len) != 0) {
        fail = "尚未获得组密钥";
        goto done;
    }
    usleep(50000);
    send_secure(n, MT_FILE_META, meta, w.len);

    double start = now_mono(), last_report = 0;
    uint64_t sent = 0;
    for (uint32_t i = 0; i < o->chunks; i++) {
        if (!n->running || n->kicked) {
            fail = "节点已停止";
            goto done;
        }
        if (send_chunk(n, o, i) != 0) {
            fail = "发送失败（密钥失效或网络错误）";
            goto done;
        }
        sent += MC_CHUNK_DATA + 60;
        rate_wait(n, start, sent);
        if (now_mono() - last_report > 0.2) {
            last_report = now_mono();
            emit_out(n, o, i + 1, TS_SENDING, "");
        }
    }
    for (int k = 0; k < 3; k++) { /* END 发三次，降低丢失概率 */
        send_end(n, o);
        usleep(100000);
    }
    {
        double el = now_mono() - start;
        char speed[64];
        snprintf(speed, sizeof(speed), "%.0f KB/s", (double)o->size / 1024.0 / (el > 1e-3 ? el : 1e-3));
        emit_out(n, o, o->chunks, TS_SENT, speed);
    }
done:
    if (fail)
        emit_out(n, o, 0, TS_FAILED, fail);
    lock(n);
    o->finished_at = now_mono();
    o->worker_active = 0;
    n->active_workers--;
    unlock(n);
    return NULL;
}

static void *resend_worker(void *arg)
{
    worker_arg *a = arg;
    node *n = a->n;
    outgoing_file *o = a->o;
    free(a);
    usleep(100000); /* 稍等片刻，合并多个接收方的补发请求 */
    while (n->running) {
        lock(n);
        uint32_t cnt = o->npending;
        uint32_t *batch = cnt ? malloc(cnt * sizeof(uint32_t)) : NULL;
        uint32_t k = 0;
        for (uint32_t i = 0; i < o->chunks && k < cnt; i++)
            if (o->pending[i]) {
                o->pending[i] = 0;
                batch[k++] = i;
            }
        o->npending = 0;
        if (!k)
            o->resend_active = 0;
        unlock(n);
        if (!k) {
            free(batch);
            break;
        }
        double start = now_mono();
        uint64_t sent = 0;
        for (uint32_t i = 0; i < k && n->running; i++) {
            send_chunk(n, o, batch[i]);
            sent += MC_CHUNK_DATA + 60;
            rate_wait(n, start, sent);
        }
        free(batch);
        send_end(n, o);
        lock(n);
        o->finished_at = now_mono();
        unlock(n);
    }
    lock(n);
    o->resend_active = 0;
    n->active_workers--;
    unlock(n);
    return NULL;
}

static outgoing_file *find_out(node *n, const uint8_t fid[MC_ID_LEN])
{
    for (int i = 0; i < MAX_OUTGOING; i++)
        if (n->out[i].used && id_eq(n->out[i].fid, fid))
            return &n->out[i];
    return NULL;
}

static void on_nack(node *n, const uint8_t *p, size_t len)
{
    rbuf r;
    rb_init(&r, p, len);
    const uint8_t *fid = rb_bytes(&r, MC_ID_LEN);
    uint8_t want_meta = rb_u8(&r);
    uint16_t nr = rb_u16(&r);
    if (r.err)
        return;
    outgoing_file *o = find_out(n, fid);
    if (!o || o->worker_active)
        return;
    if (want_meta) {
        uint8_t meta[512];
        wbuf w;
        wb_init(&w, meta, sizeof(meta));
        pack_meta(o, &w);
        send_secure(n, MT_FILE_META, meta, w.len);
    }
    for (uint16_t i = 0; i < nr; i++) {
        uint32_t lo = rb_u32(&r), hi = rb_u32(&r);
        if (r.err)
            break;
        for (uint32_t c = lo; c <= hi && c < o->chunks; c++) {
            if (!o->pending[c]) {
                o->pending[c] = 1;
                o->npending++;
            }
        }
    }
    if (o->npending && !o->resend_active) {
        o->resend_active = 1;
        n->active_workers++;
        worker_arg *a = malloc(sizeof(*a));
        a->n = n;
        a->o = o;
        pthread_t t;
        if (pthread_create(&t, NULL, resend_worker, a) == 0) {
            pthread_detach(t);
        } else {
            free(a);
            o->resend_active = 0;
            n->active_workers--;
        }
    }
}

/* ======================================================== 文件接收 */

static incoming_file *find_in(node *n, const uint8_t fid[MC_ID_LEN])
{
    for (int i = 0; i < MAX_INCOMING; i++)
        if (n->in[i].used && id_eq(n->in[i].fid, fid))
            return &n->in[i];
    return NULL;
}

static void request_meta(node *n, const uint8_t fid[MC_ID_LEN])
{
    double t = now_mono();
    id_time *slot = NULL, *oldest = &n->meta_req[0];
    for (int i = 0; i < 16; i++) {
        if (id_eq(n->meta_req[i].id, fid))
            slot = &n->meta_req[i];
        if (n->meta_req[i].t < oldest->t)
            oldest = &n->meta_req[i];
    }
    if (slot && t - slot->t < 2.0)
        return;
    if (!slot) {
        slot = oldest;
        memcpy(slot->id, fid, MC_ID_LEN);
    }
    slot->t = t;
    uint8_t buf[16];
    wbuf w;
    wb_init(&w, buf, sizeof(buf));
    wb_bytes(&w, fid, MC_ID_LEN);
    wb_u8(&w, 1);
    wb_u16(&w, 0);
    send_secure(n, MT_NACK, buf, w.len);
}

static void finish_in(node *n, incoming_file *f)
{
    char reason[160];
    int ok = incoming_finalize(f, reason, sizeof(reason));
    emit_in(n, f, ok ? TS_DONE : TS_FAILED, reason);
}

static void fail_in(node *n, incoming_file *f, const char *reason)
{
    incoming_fail(f);
    emit_in(n, f, TS_FAILED, reason);
}

static void on_file_meta(node *n, const uint8_t *sender, const char *sender_name, const uint8_t *p, size_t len)
{
    rbuf r;
    rb_init(&r, p, len);
    const uint8_t *fid = rb_bytes(&r, MC_ID_LEN);
    uint8_t fidc[MC_ID_LEN];
    memcpy(fidc, fid, MC_ID_LEN);
    uint64_t size = rb_u64(&r);
    uint32_t chunks = rb_u32(&r);
    const uint8_t *sha = rb_bytes(&r, 32);
    uint8_t shac[32];
    memcpy(shac, sha, 32);
    char name[256];
    rb_str16(&r, name, sizeof(name));
    if (r.err || chunks != chunk_count(size) || find_in(n, fidc))
        return;

    incoming_file *f = NULL;
    for (int i = 0; i < MAX_INCOMING && !f; i++)
        if (!n->in[i].used)
            f = &n->in[i];
    if (!f) { /* 回收最早结束的条目 */
        for (int i = 0; i < MAX_INCOMING; i++)
            if (n->in[i].state != IN_RECEIVING && (!f || n->in[i].created < f->created))
                f = &n->in[i];
        if (!f)
            return;
        incoming_release(f);
    }
    memset(f, 0, sizeof(*f));
    f->fd = -1;
    memcpy(f->fid, fidc, MC_ID_LEN);
    memcpy(f->sender, sender, MC_ID_LEN);
    snprintf(f->sender_name, sizeof(f->sender_name), "%s", sender_name);
    safe_filename(name, f->name, sizeof(f->name));
    f->size = size;
    f->chunks = chunks;
    memcpy(f->sha, shac, 32);
    f->created = f->last_activity = now_mono();
    f->received_at_last_nack = -1;
    char err[160];
    if (incoming_open(f, n->dl_dir, err, sizeof(err)) != 0) {
        sys_msg(n, "无法接收文件 %s：%s", f->name, err);
        free(f->bitmap);
        memset(f, 0, sizeof(*f));
        f->fd = -1;
        return;
    }
    f->used = 1;
    emit_in(n, f, TS_RECEIVING, "");
    if (f->chunks == 0)
        finish_in(n, f);
}

static void on_file_chunk(node *n, const uint8_t *sender, const uint8_t *p, size_t len)
{
    if (len < MC_ID_LEN + 4)
        return;
    rbuf r;
    rb_init(&r, p, len);
    const uint8_t *fid = rb_bytes(&r, MC_ID_LEN);
    uint32_t idx = rb_u32(&r);
    incoming_file *f = find_in(n, fid);
    if (!f) {
        if (n->cfg.retransmit)
            request_meta(n, fid);
        return;
    }
    if (!id_eq(f->sender, sender))
        return;
    f->last_activity = now_mono();
    if (incoming_write(f, idx, p + r.pos, len - r.pos)) {
        if (f->received == f->chunks) {
            finish_in(n, f);
        } else if (f->last_activity - f->last_report > 0.2) {
            f->last_report = f->last_activity;
            emit_in(n, f, TS_RECEIVING, "");
        }
    }
}

static void on_file_end(node *n, const uint8_t *p, size_t len)
{
    if (len < MC_ID_LEN)
        return;
    incoming_file *f = find_in(n, p);
    if (!f) {
        if (n->cfg.retransmit)
            request_meta(n, p);
        return;
    }
    f->end_seen = 1;
    f->last_activity = now_mono();
}

static void check_incoming(node *n, double t)
{
    for (int i = 0; i < MAX_INCOMING; i++) {
        incoming_file *f = &n->in[i];
        if (!f->used || f->state != IN_RECEIVING)
            continue;
        if (f->received == f->chunks) {
            finish_in(n, f);
            continue;
        }
        double idle = t - f->last_activity;
        if (!f->end_seen && idle < INACTIVITY_TIMEOUT)
            continue;
        if (f->end_seen && idle < 0.3)
            continue; /* 刚收到 END，再等一下乱序到达的分片 */
        uint32_t missing = f->chunks - f->received;
        char reason[160];
        if (!n->cfg.retransmit) {
            snprintf(reason, sizeof(reason), "丢失 %u 个分片（未开启丢包重传）", missing);
            fail_in(n, f, reason);
            continue;
        }
        if (!mt_find(&n->mt, f->sender)) {
            snprintf(reason, sizeof(reason), "发送方已离开，仍缺 %u 个分片", missing);
            fail_in(n, f, reason);
            continue;
        }
        if (t < f->next_nack)
            continue;
        if ((int64_t)f->received == f->received_at_last_nack)
            f->nack_rounds++;
        else
            f->nack_rounds = 0;
        if (f->nack_rounds >= MAX_NACK_ROUNDS) {
            snprintf(reason, sizeof(reason), "多次请求补发无果，仍缺 %u 个分片", missing);
            fail_in(n, f, reason);
            continue;
        }
        f->received_at_last_nack = f->received;
        f->next_nack = t + 1.0 + f->nack_rounds;

        /* NACK：fid + want_meta(0) + 区间个数 + [lo,hi]... 缺失分片压缩成区间 */
        uint8_t buf[MC_ID_LEN + 3 + MAX_NACK_RANGES * 8];
        wbuf w;
        wb_init(&w, buf, sizeof(buf));
        wb_bytes(&w, f->fid, MC_ID_LEN);
        wb_u8(&w, 0);
        size_t cnt_pos = w.len;
        wb_u16(&w, 0);
        uint16_t nr = 0;
        for (uint32_t c = 0; c < f->chunks && nr < MAX_NACK_RANGES;) {
            if (f->bitmap[c]) {
                c++;
                continue;
            }
            uint32_t lo = c;
            while (c < f->chunks && !f->bitmap[c])
                c++;
            wb_u32(&w, lo);
            wb_u32(&w, c - 1);
            nr++;
        }
        buf[cnt_pos] = (uint8_t)(nr >> 8);
        buf[cnt_pos + 1] = (uint8_t)nr;
        send_secure(n, MT_NACK, buf, w.len);
        snprintf(reason, sizeof(reason), "请求补发 %u 个分片", missing);
        emit_in(n, f, TS_RECEIVING, reason);
    }
}

/* ======================================================== 接收主循环 */

static int decrypt_payload(node *n, const msg_header *h, const uint8_t *raw, const uint8_t *p, size_t len,
                           uint8_t *out)
{
    if (!n->cfg.encrypt) {
        if (h->epoch != 0) {
            warn_once(n, h->sender, "对方开启了加密而本机未开启，忽略其消息");
            return -1;
        }
        memcpy(out, p, len);
        return (int)len;
    }
    if (h->epoch == 0) {
        warn_once(n, h->sender, "对方未开启加密，本机拒收明文消息");
        return -1;
    }
    group_key *k = key_for(n, h->epoch);
    if (!k) {
        double t = now_mono();
        if (t - n->undecryptable_warned > 5 && is_ready(n)) {
            n->undecryptable_warned = t;
            sys_msg(n, "收到无法解密的数据（密钥版本 %u，本机为 %u），已丢弃", h->epoch, n->epoch);
        }
        n->st_dropped++;
        return -1;
    }
    int r = gcm_open(k->key, p, len, raw, MC_HEADER_SIZE, out);
    if (r < 0)
        n->st_dropped++;
    return r;
}

static void handle_datagram(node *n, const uint8_t *data, size_t len, const char *addr)
{
    msg_header h;
    if (hdr_parse(data, len, &h) != 0 || id_eq(h.sender, n->idn.id))
        return;
    if (n->drop_hook && n->drop_hook(&h, n->drop_user))
        return;
    const uint8_t *p = data + MC_HEADER_SIZE;
    size_t plen = len - MC_HEADER_SIZE;

    lock(n);
    if (n->kicked)
        goto out;
    n->st_recv++;
    if (h.type == MT_HELLO || h.type == MT_HEARTBEAT) {
        on_presence(n, &h, p, plen, addr);
        goto out;
    }
    if (mt_is_banned(&n->mt, h.sender))
        goto out;
    switch (h.type) {
    case MT_BYE: on_bye(n, h.sender); goto out;
    case MT_KEY_DIST: on_key_dist(n, h.sender, p, plen); goto out;
    case MT_KICK: on_kick(n, h.sender, p, plen); goto out;
    default: break;
    }

    static __thread uint8_t pt[MC_MAX_DATAGRAM];
    int ptlen = decrypt_payload(n, &h, data, p, plen, pt);
    if (ptlen < 0)
        goto out;
    member *m = mt_find(&n->mt, h.sender);
    char sname[MC_MAX_NAME + 1];
    if (m)
        snprintf(sname, sizeof(sname), "%s", m->name);
    else
        id_to_hex(h.sender, sname), sname[6] = 0;

    switch (h.type) {
    case MT_CHAT: {
        node_event ev = {.kind = EV_CHAT};
        size_t tl = (size_t)ptlen < MC_MAX_TEXT ? (size_t)ptlen : MC_MAX_TEXT;
        memcpy(ev.text, pt, tl);
        ev.text[tl] = 0;
        id_to_hex(h.sender, ev.id);
        snprintf(ev.name, sizeof(ev.name), "%s", sname);
        emit(n, &ev);
        break;
    }
    case MT_FILE_META: on_file_meta(n, h.sender, sname, pt, (size_t)ptlen); break;
    case MT_FILE_CHUNK: on_file_chunk(n, h.sender, pt, (size_t)ptlen); break;
    case MT_FILE_END: on_file_end(n, pt, (size_t)ptlen); break;
    case MT_NACK: on_nack(n, pt, (size_t)ptlen); break;
    default: break;
    }
out:
    unlock(n);
}

static void *recv_loop(void *arg)
{
    node *n = arg;
    static __thread uint8_t buf[MC_MAX_DATAGRAM];
    while (n->running) {
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        ssize_t r = recvfrom(n->fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
        if (r < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                usleep(100000);
            continue;
        }
        char addr[16];
        inet_ntop(AF_INET, &src.sin_addr, addr, sizeof(addr));
        handle_datagram(n, buf, (size_t)r, addr);
    }
    return NULL;
}

/* ======================================================== 定时任务 */

static void *timer_loop(void *arg)
{
    node *n = arg;
    while (n->running) {
        usleep(TICK_US);
        lock(n);
        if (n->kicked || n->frozen) {
            unlock(n);
            continue;
        }
        double t = now_mono();
        if (t >= n->next_heartbeat) {
            n->next_heartbeat = t + HEARTBEAT_INTERVAL;
            send_presence(n, MT_HEARTBEAT);
        }
        /* 超时成员 */
        for (int i = 0; i < MAX_MEMBERS; i++) {
            member *m = &n->mt.m[i];
            if (m->used && t - m->last_seen > MEMBER_TIMEOUT) {
                uint8_t id[MC_ID_LEN];
                memcpy(id, m->id, MC_ID_LEN);
                sys_msg(n, "%s 超时未响应，判定为离线", m->name);
                mt_remove(m);
                member_gone(n, id);
            }
        }
        /* 发现阶段结束 / 管理员缺位 → 选举 */
        int end_disc = n->discovering && t >= n->discovery_deadline;
        if (end_disc)
            n->discovering = 0;
        if (!n->discovering && !n->is_admin && !n->has_admin) {
            if (end_disc)
                sys_msg(n, "未发现管理员");
            elect(n);
        }
        /* 清理过期旧密钥 */
        for (int i = 0; i < MAX_KEYS; i++)
            if (n->keys[i].used && n->keys[i].expiry > 0 && t > n->keys[i].expiry &&
                n->keys[i].epoch != n->epoch)
                memset(&n->keys[i], 0, sizeof(group_key));
        /* 清理过期的已发送文件 */
        for (int i = 0; i < MAX_OUTGOING; i++) {
            outgoing_file *o = &n->out[i];
            if (o->used && o->finished_at > 0 && !o->worker_active && !o->resend_active &&
                t - o->finished_at > OUTGOING_RETAIN)
                outgoing_close(o);
        }
        check_incoming(n, t);
        unlock(n);
    }
    return NULL;
}

/* ======================================================== 对外接口 */

void node_config_default(node_config *c)
{
    memset(c, 0, sizeof(*c));
    gethostname(c->name, sizeof(c->name) - 1);
    strcpy(c->group, "239.1.2.3");
    c->port = 50000;
    c->ttl = 1;
    c->encrypt = 1;
    c->retransmit = 0;
    c->rate_kbps = 2048;
}

node *node_create(const node_config *cfg, node_event_cb cb, void *user)
{
    node *n = calloc(1, sizeof(node));
    if (!n)
        return NULL;
    n->cfg = *cfg;
    if (!n->cfg.name[0])
        strcpy(n->cfg.name, "匿名");
    if (!n->cfg.iface[0])
        guess_local_ip(n->cfg.iface);
    if (n->cfg.rate_kbps < 64)
        n->cfg.rate_kbps = 64;
    n->cb = cb;
    n->user = user;
    n->fd = -1;
    if (identity_generate(&n->idn) != 0) {
        free(n);
        return NULL;
    }
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&n->lk, &a);
    pthread_mutexattr_destroy(&a);
    for (int i = 0; i < MAX_OUTGOING; i++)
        n->out[i].fd = -1;
    for (int i = 0; i < MAX_INCOMING; i++)
        n->in[i].fd = -1;

    /* 下载目录：<base>/<昵称>-<ID前6位> */
    char base[MC_PATH - 64], idh[17], safe[MC_MAX_NAME + 1];
    if (cfg->download_dir[0])
        snprintf(base, sizeof(base), "%s", cfg->download_dir);
    else
        snprintf(base, sizeof(base), "%s/McastChat", getenv("HOME") ? getenv("HOME") : ".");
    id_to_hex(n->idn.id, idh);
    idh[6] = 0;
    safe_filename(n->cfg.name, safe, sizeof(safe));
    snprintf(n->dl_dir, sizeof(n->dl_dir), "%s/%s-%s", base, safe, idh);
    return n;
}

int node_start(node *n, char *err, size_t errlen)
{
    n->fd = open_multicast_socket(n->cfg.group, n->cfg.port, n->cfg.iface, n->cfg.ttl, err, errlen);
    if (n->fd < 0)
        return -1;
    n->since = now_wall();
    n->discovering = 1;
    n->discovery_deadline = now_mono() + DISCOVERY_TIME;
    n->next_heartbeat = 0;
    n->running = 1;
    pthread_create(&n->th_recv, NULL, recv_loop, n);
    pthread_create(&n->th_timer, NULL, timer_loop, n);
    lock(n);
    sys_msg(n, "已加入多播组 %s:%d（网卡 %s），正在发现组内成员…", n->cfg.group, n->cfg.port, n->cfg.iface);
    send_presence(n, MT_HELLO);
    emit_simple(n, EV_MEMBERS);
    unlock(n);
    return 0;
}

void node_stop(node *n)
{
    if (!n->running)
        return;
    /* 先停掉线程，保证 BYE 之后不会再发出心跳 */
    n->running = 0;
    pthread_join(n->th_recv, NULL);
    pthread_join(n->th_timer, NULL);
    for (int i = 0; i < 300; i++) { /* 等文件工作线程退出，最多 3 秒 */
        lock(n);
        int w = n->active_workers;
        unlock(n);
        if (!w)
            break;
        usleep(10000);
    }
    if (!n->kicked) {
        send_raw(n, MT_BYE, NULL, 0, 0);
        send_raw(n, MT_BYE, NULL, 0, 0);
    }
    leave_multicast_group(n->fd, n->cfg.group, n->cfg.iface);
    close(n->fd);
    n->fd = -1;
    lock(n);
    for (int i = 0; i < MAX_INCOMING; i++)
        if (n->in[i].used)
            incoming_release(&n->in[i]);
    unlock(n);
}

void node_destroy(node *n)
{
    if (!n)
        return;
    node_stop(n);
    for (int i = 0; i < MAX_OUTGOING; i++)
        if (n->out[i].used && !n->out[i].worker_active && !n->out[i].resend_active)
            outgoing_close(&n->out[i]);
    for (int i = 0; i < MAX_MEMBERS; i++)
        if (n->mt.m[i].used)
            mt_remove(&n->mt.m[i]);
    identity_free(&n->idn);
    pthread_mutex_destroy(&n->lk);
    free(n);
}

int node_send_chat(node *n, const char *text, char *err, size_t errlen)
{
    while (*text == ' ' || *text == '\t' || *text == '\n')
        text++;
    size_t len = strlen(text);
    if (!len)
        return 0;
    if (len > MC_MAX_TEXT) {
        snprintf(err, errlen, "消息过长（最多 %d 字节）", MC_MAX_TEXT);
        return -1;
    }
    if (n->kicked || send_secure(n, MT_CHAT, (const uint8_t *)text, len) != 0) {
        snprintf(err, errlen, "尚未获得组密钥，暂时不能发送");
        return -1;
    }
    node_event ev = {.kind = EV_CHAT, .self = 1};
    snprintf(ev.text, sizeof(ev.text), "%s", text);
    snprintf(ev.name, sizeof(ev.name), "%s", n->cfg.name);
    id_to_hex(n->idn.id, ev.id);
    emit(n, &ev);
    return 0;
}

int node_send_file(node *n, const char *path, char *err, size_t errlen)
{
    lock(n);
    if (!is_ready(n) || n->kicked) {
        unlock(n);
        snprintf(err, errlen, "尚未获得组密钥，暂时不能发送");
        return -1;
    }
    outgoing_file *o = NULL;
    for (int i = 0; i < MAX_OUTGOING && !o; i++)
        if (!n->out[i].used)
            o = &n->out[i];
    for (int i = 0; i < MAX_OUTGOING && !o; i++) /* 没有空位：回收已过补发期之外最早的 */
        if (n->out[i].finished_at > 0 && !n->out[i].worker_active && !n->out[i].resend_active) {
            outgoing_close(&n->out[i]);
            o = &n->out[i];
        }
    if (!o) {
        unlock(n);
        snprintf(err, errlen, "同时发送的文件过多");
        return -1;
    }
    uint8_t fid[MC_ID_LEN];
    random_bytes(fid, MC_ID_LEN);
    if (outgoing_open(o, fid, path, err, errlen) != 0) {
        unlock(n);
        return -1;
    }
    o->worker_active = 1;
    n->active_workers++;
    worker_arg *a = malloc(sizeof(*a));
    a->n = n;
    a->o = o;
    pthread_t t;
    if (pthread_create(&t, NULL, send_file_worker, a) != 0) {
        free(a);
        outgoing_close(o);
        n->active_workers--;
        unlock(n);
        snprintf(err, errlen, "无法创建发送线程");
        return -1;
    }
    pthread_detach(t);
    unlock(n);
    return 0;
}

int node_kick(node *n, const char *id_hex, char *err, size_t errlen)
{
    uint8_t target[MC_ID_LEN];
    if (hex_to_id(id_hex, target) != 0) {
        snprintf(err, errlen, "成员 ID 不合法");
        return -1;
    }
    lock(n);
    int rc = -1;
    if (!n->is_admin) {
        snprintf(err, errlen, "只有管理员可以删除成员");
    } else if (id_eq(target, n->idn.id)) {
        snprintf(err, errlen, "不能删除自己");
    } else {
        member *m = mt_find(&n->mt, target);
        char name[MC_MAX_NAME + 1];
        snprintf(name, sizeof(name), "%s", m ? m->name : id_hex);
        if (m)
            mt_remove(m);
        mt_ban(&n->mt, target);
        send_kick(n, target, 0);
        sys_msg(n, "你已将 %s 移出群组%s", name, n->cfg.encrypt ? "，正在更换组密钥" : "");
        emit_simple(n, EV_MEMBERS);
        if (n->cfg.encrypt)
            rotate_key(n, 1); /* 立即丢弃旧密钥：被删除者拿不到新密钥 */
        rc = 0;
    }
    unlock(n);
    return rc;
}

int node_members(node *n, member_info *out, int max)
{
    if (max <= 0)
        return 0;
    lock(n);
    member_info *me = &out[0];
    memset(me, 0, sizeof(*me));
    id_to_hex(n->idn.id, me->id);
    snprintf(me->name, sizeof(me->name), "%s", n->cfg.name);
    snprintf(me->addr, sizeof(me->addr), "%s", n->cfg.iface);
    me->admin = n->is_admin;
    me->has_key = is_ready(n);
    me->epoch = n->epoch;
    me->self = 1;
    member *list[MAX_MEMBERS];
    int cnt = mt_sorted(&n->mt, list, MAX_MEMBERS), k = 1;
    for (int i = 0; i < cnt && k < max; i++, k++) {
        member_info *mi = &out[k];
        memset(mi, 0, sizeof(*mi));
        id_to_hex(list[i]->id, mi->id);
        snprintf(mi->name, sizeof(mi->name), "%s", list[i]->name);
        snprintf(mi->addr, sizeof(mi->addr), "%s", list[i]->addr);
        mi->admin = list[i]->is_admin;
        mi->has_key = list[i]->has_key;
        mi->epoch = list[i]->epoch;
    }
    unlock(n);
    return k;
}

int node_is_admin(node *n) { lock(n); int v = n->is_admin; unlock(n); return v; }
int node_ready(node *n) { lock(n); int v = is_ready(n) && !n->kicked; unlock(n); return v; }
int node_kicked(node *n) { lock(n); int v = n->kicked; unlock(n); return v; }
uint32_t node_epoch(node *n) { lock(n); uint32_t v = n->epoch; unlock(n); return v; }
const node_config *node_get_config(node *n) { return &n->cfg; }
const char *node_download_dir(node *n) { return n->dl_dir; }
void node_id_hex(node *n, char out[2 * MC_ID_LEN + 1]) { id_to_hex(n->idn.id, out); }

void node_stats(node *n, unsigned long *sent, unsigned long *recv, unsigned long *dropped)
{
    *sent = __atomic_load_n(&n->st_sent, __ATOMIC_RELAXED);
    lock(n);
    *recv = n->st_recv;
    *dropped = n->st_dropped;
    unlock(n);
}

void node_set_drop_hook(node *n, node_drop_hook hook, void *user)
{
    lock(n);
    n->drop_hook = hook;
    n->drop_user = user;
    unlock(n);
}

void node_test_set_kicked(node *n, int kicked) { lock(n); n->kicked = kicked; unlock(n); }

void node_test_copy_key(node *dst, node *src)
{
    lock(src);
    group_key k = *key_for(src, src->epoch);
    unlock(src);
    lock(dst);
    install_key(dst, k.epoch, k.key);
    unlock(dst);
}

void node_test_send_kick(node *n, const char *target_hex)
{
    uint8_t t[MC_ID_LEN];
    if (hex_to_id(target_hex, t) == 0) {
        lock(n);
        send_kick(n, t, 0);
        unlock(n);
    }
}

void node_test_freeze(node *n) { lock(n); n->frozen = 1; unlock(n); }
