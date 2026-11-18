/*
 * protocol.h —— 报文格式定义
 *
 * 每个 UDP 数据报 = 20 字节定长头部 + 载荷。头部字段（网络字节序）：
 *   magic      2B  固定为 "MC"，用于过滤无关数据包
 *   version    1B  协议版本
 *   type       1B  报文类型（enum msg_type）
 *   sender_id  8B  发送者节点 ID（RSA 公钥 DER 的 SHA-256 前 8 字节）
 *   seq        4B  发送者自增序号
 *   key_epoch  4B  所用组密钥版本，0 表示明文
 *
 * 加密报文的载荷 = nonce(12B) + AES-256-GCM 密文 + tag(16B)，
 * 整个 20 字节头部作为 GCM 的附加认证数据(AAD)，头部被篡改也会认证失败。
 *
 * 各类型载荷均为二进制定长/带长度前缀的字段，见 node.c 中的编解码。
 */
#ifndef MC_PROTOCOL_H
#define MC_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define MC_MAGIC0 'M'
#define MC_MAGIC1 'C'
#define MC_VERSION 1
#define MC_HEADER_SIZE 20
#define MC_ID_LEN 8
#define MC_MAX_DATAGRAM 65507

/* 文件分片数据长度：20(头) + 12(nonce) + 12(分片头) + 1200 + 16(tag) + 28(IP/UDP)
 * = 1288 字节 < 以太网 MTU 1500，不会被 IP 分片 */
#define MC_CHUNK_DATA 1200
#define MC_MAX_TEXT 4000
#define MC_MAX_NAME 32

enum msg_type {
    MT_HELLO = 1,      /* 上线通告（明文）：昵称、公钥、上线时间 */
    MT_HEARTBEAT = 2,  /* 心跳（明文）：同上，另含是否管理员、持有的密钥版本 */
    MT_BYE = 3,        /* 主动下线（明文） */
    MT_KEY_DIST = 4,   /* 组密钥分发（RSA-OAEP 加密 + 管理员 RSA-PSS 签名） */
    MT_KICK = 5,       /* 删除成员（管理员签名） */
    MT_CHAT = 10,      /* 聊天文本（AES-GCM） */
    MT_FILE_META = 11, /* 文件元信息（AES-GCM） */
    MT_FILE_CHUNK = 12,/* 文件分片（AES-GCM） */
    MT_FILE_END = 13,  /* 文件发送结束（AES-GCM） */
    MT_NACK = 14       /* 请求补发缺失分片（AES-GCM，可选功能） */
};

typedef struct {
    uint8_t type;
    uint8_t sender[MC_ID_LEN];
    uint32_t seq;
    uint32_t epoch;
} msg_header;

void hdr_pack(const msg_header *h, uint8_t out[MC_HEADER_SIZE]);
/* 解析头部，成功返回 0；magic/版本/类型不合法返回 -1 */
int hdr_parse(const uint8_t *data, size_t len, msg_header *h);
int msg_is_encrypted_type(int type);
const char *msg_type_name(int type);

/* ---------- 带边界检查的二进制读写 ---------- */
typedef struct {
    uint8_t *p;
    size_t len, cap;
    int err;
} wbuf;

typedef struct {
    const uint8_t *p;
    size_t len, pos;
    int err;
} rbuf;

void wb_init(wbuf *w, uint8_t *mem, size_t cap);
void wb_u8(wbuf *w, uint8_t v);
void wb_u16(wbuf *w, uint16_t v);
void wb_u32(wbuf *w, uint32_t v);
void wb_u64(wbuf *w, uint64_t v);
void wb_bytes(wbuf *w, const void *src, size_t n);
void wb_str16(wbuf *w, const char *s); /* u16 长度 + 字节 */

void rb_init(rbuf *r, const uint8_t *p, size_t len);
uint8_t rb_u8(rbuf *r);
uint16_t rb_u16(rbuf *r);
uint32_t rb_u32(rbuf *r);
uint64_t rb_u64(rbuf *r);
const uint8_t *rb_bytes(rbuf *r, size_t n);
/* 读取 u16 长度前缀的字符串到 out（截断并补 0），返回 0 成功 */
int rb_str16(rbuf *r, char *out, size_t outcap);
size_t rb_left(const rbuf *r);

/* 工具 */
void id_to_hex(const uint8_t id[MC_ID_LEN], char out[2 * MC_ID_LEN + 1]);
int hex_to_id(const char *hex, uint8_t id[MC_ID_LEN]);

#endif
