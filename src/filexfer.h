/*
 * filexfer.h —— 文件的分片发送与重组接收
 *
 * UDP 不可靠且单个数据报有大小限制，因此：
 *   - 发送方先多播 FILE_META（文件名、大小、分片数、SHA-256），
 *     再按序号多播 FILE_CHUNK，最后多播 FILE_END；
 *   - 接收方把分片写到文件对应偏移，用位图记录收到哪些分片；
 *   - 收齐后计算整个文件的 SHA-256 与 FILE_META 比对，一致才算成功；
 *   - （可选）缺片时接收方多播 NACK，发送方补发对应分片。
 */
#ifndef MC_FILEXFER_H
#define MC_FILEXFER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "protocol.h"

#define MAX_OUTGOING 16
#define MAX_INCOMING 32
#define OUTGOING_RETAIN 120.0   /* 发送方保留文件以响应补发请求的时长（秒） */
#define INACTIVITY_TIMEOUT 4.0  /* 没收到 FILE_END 时，空闲多久开始检查完整性 */
#define MAX_NACK_ROUNDS 6       /* 连续多少轮 NACK 没有进展就放弃 */
#define MC_PATH 1024

enum { IN_RECEIVING = 0, IN_DONE = 1, IN_FAILED = 2 };

typedef struct {
    int used;
    uint8_t fid[MC_ID_LEN];
    char path[MC_PATH];
    char name[256];
    uint64_t size;
    uint32_t chunks;
    uint8_t sha[32];
    int fd;
    double finished_at;   /* 0 = 尚未发送完 */
    int worker_active;
    uint8_t *pending;     /* 待补发分片位图 */
    uint32_t npending;
    int resend_active;
} outgoing_file;

typedef struct {
    int used;
    uint8_t fid[MC_ID_LEN];
    uint8_t sender[MC_ID_LEN];
    char sender_name[MC_MAX_NAME + 1];
    char name[256];
    uint64_t size;
    uint32_t chunks;
    uint8_t sha[32];
    char dir[MC_PATH];
    char part_path[MC_PATH + 300];
    char final_path[MC_PATH + 300];
    int fd;
    uint8_t *bitmap;
    uint32_t received;
    int state;
    int end_seen;
    double created;
    double last_activity;
    double last_report;
    int nack_rounds;
    double next_nack;
    int64_t received_at_last_nack;
} incoming_file;

uint32_t chunk_count(uint64_t size);
int is_media_file(const char *name);
/* 去掉路径与非法字符，防止对方用 ../ 之类的文件名写到下载目录以外 */
void safe_filename(const char *in, char *out, size_t cap);
void unique_path(const char *dir, const char *name, char *out, size_t cap);
int mkdir_p(const char *path);

int outgoing_open(outgoing_file *o, const uint8_t fid[MC_ID_LEN], const char *path,
                  char *err, size_t errlen);
ssize_t outgoing_read(outgoing_file *o, uint32_t index, uint8_t *buf);
void outgoing_close(outgoing_file *o);

int incoming_open(incoming_file *f, const char *dir, char *err, size_t errlen);
/* 写入一个分片：新分片返回 1，重复或非法返回 0 */
int incoming_write(incoming_file *f, uint32_t index, const uint8_t *data, size_t len);
/* 收齐后校验并改名：成功返回 1 */
int incoming_finalize(incoming_file *f, char *reason, size_t cap);
void incoming_fail(incoming_file *f);
void incoming_release(incoming_file *f);

#endif
