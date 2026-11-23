#include "protocol.h"

#include <stdio.h>
#include <string.h>

void hdr_pack(const msg_header *h, uint8_t out[MC_HEADER_SIZE])
{
    wbuf w;
    wb_init(&w, out, MC_HEADER_SIZE);
    wb_u8(&w, MC_MAGIC0);
    wb_u8(&w, MC_MAGIC1);
    wb_u8(&w, MC_VERSION);
    wb_u8(&w, h->type);
    wb_bytes(&w, h->sender, MC_ID_LEN);
    wb_u32(&w, h->seq);
    wb_u32(&w, h->epoch);
}

int hdr_parse(const uint8_t *data, size_t len, msg_header *h)
{
    if (len < MC_HEADER_SIZE)
        return -1;
    if (data[0] != MC_MAGIC0 || data[1] != MC_MAGIC1 || data[2] != MC_VERSION)
        return -1;
    rbuf r;
    rb_init(&r, data + 3, MC_HEADER_SIZE - 3);
    h->type = rb_u8(&r);
    memcpy(h->sender, rb_bytes(&r, MC_ID_LEN), MC_ID_LEN);
    h->seq = rb_u32(&r);
    h->epoch = rb_u32(&r);
    switch (h->type) {
    case MT_HELLO: case MT_HEARTBEAT: case MT_BYE: case MT_KEY_DIST: case MT_KICK:
    case MT_CHAT: case MT_FILE_META: case MT_FILE_CHUNK: case MT_FILE_END: case MT_NACK:
        return 0;
    default:
        return -1;
    }
}

int msg_is_encrypted_type(int type)
{
    return type == MT_CHAT || type == MT_FILE_META || type == MT_FILE_CHUNK ||
           type == MT_FILE_END || type == MT_NACK;
}

const char *msg_type_name(int type)
{
    switch (type) {
    case MT_HELLO: return "HELLO";
    case MT_HEARTBEAT: return "HEARTBEAT";
    case MT_BYE: return "BYE";
    case MT_KEY_DIST: return "KEY_DIST";
    case MT_KICK: return "KICK";
    case MT_CHAT: return "CHAT";
    case MT_FILE_META: return "FILE_META";
    case MT_FILE_CHUNK: return "FILE_CHUNK";
    case MT_FILE_END: return "FILE_END";
    case MT_NACK: return "NACK";
    default: return "?";
    }
}

/* ---------------- wbuf ---------------- */

void wb_init(wbuf *w, uint8_t *mem, size_t cap)
{
    w->p = mem;
    w->len = 0;
    w->cap = cap;
    w->err = 0;
}

void wb_bytes(wbuf *w, const void *src, size_t n)
{
    if (w->err || w->len + n > w->cap) {
        w->err = 1;
        return;
    }
    if (n)
        memcpy(w->p + w->len, src, n);
    w->len += n;
}

void wb_u8(wbuf *w, uint8_t v) { wb_bytes(w, &v, 1); }

void wb_u16(wbuf *w, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    wb_bytes(w, b, 2);
}

void wb_u32(wbuf *w, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    wb_bytes(w, b, 4);
}

void wb_u64(wbuf *w, uint64_t v)
{
    wb_u32(w, (uint32_t)(v >> 32));
    wb_u32(w, (uint32_t)v);
}

void wb_str16(wbuf *w, const char *s)
{
    size_t n = strlen(s);
    if (n > 0xFFFF) {
        w->err = 1;
        return;
    }
    wb_u16(w, (uint16_t)n);
    wb_bytes(w, s, n);
}

/* ---------------- rbuf ---------------- */

void rb_init(rbuf *r, const uint8_t *p, size_t len)
{
    r->p = p;
    r->len = len;
    r->pos = 0;
    r->err = 0;
}

const uint8_t *rb_bytes(rbuf *r, size_t n)
{
    static const uint8_t zeros[64];
    if (r->err || r->pos + n > r->len) {
        r->err = 1;
        return zeros; /* 出错时返回全 0 缓冲区，调用方最后检查 err */
    }
    const uint8_t *q = r->p + r->pos;
    r->pos += n;
    return q;
}

uint8_t rb_u8(rbuf *r) { return rb_bytes(r, 1)[0]; }

uint16_t rb_u16(rbuf *r)
{
    const uint8_t *b = rb_bytes(r, 2);
    return (uint16_t)((b[0] << 8) | b[1]);
}

uint32_t rb_u32(rbuf *r)
{
    const uint8_t *b = rb_bytes(r, 4);
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

uint64_t rb_u64(rbuf *r)
{
    uint64_t hi = rb_u32(r);
    return (hi << 32) | rb_u32(r);
}

int rb_str16(rbuf *r, char *out, size_t outcap)
{
    uint16_t n = rb_u16(r);
    if (r->err || r->pos + n > r->len) {
        r->err = 1;
        out[0] = 0;
        return -1;
    }
    size_t c = n < outcap - 1 ? n : outcap - 1;
    memcpy(out, r->p + r->pos, c);
    out[c] = 0;
    r->pos += n;
    return 0;
}

size_t rb_left(const rbuf *r) { return r->err ? 0 : r->len - r->pos; }

void id_to_hex(const uint8_t id[MC_ID_LEN], char out[2 * MC_ID_LEN + 1])
{
    for (int i = 0; i < MC_ID_LEN; i++)
        sprintf(out + 2 * i, "%02x", id[i]);
}

int hex_to_id(const char *hex, uint8_t id[MC_ID_LEN])
{
    if (strlen(hex) != 2 * MC_ID_LEN)
        return -1;
    for (int i = 0; i < MC_ID_LEN; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        id[i] = (uint8_t)v;
    }
    return 0;
}
