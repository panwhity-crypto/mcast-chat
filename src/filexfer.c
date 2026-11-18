#include "filexfer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"

uint32_t chunk_count(uint64_t size)
{
    return (uint32_t)((size + MC_CHUNK_DATA - 1) / MC_CHUNK_DATA);
}

int is_media_file(const char *name)
{
    static const char *exts[] = {".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma",
                                 ".mp4", ".mkv", ".avi", ".mov", ".webm", ".wmv", ".flv", ".m4v", NULL};
    const char *dot = strrchr(name, '.');
    if (!dot)
        return 0;
    for (int i = 0; exts[i]; i++)
        if (strcasecmp(dot, exts[i]) == 0)
            return 1;
    return 0;
}

void safe_filename(const char *in, char *out, size_t cap)
{
    const char *base = in;
    for (const char *p = in; *p; p++)
        if (*p == '/' || *p == '\\')
            base = p + 1;
    size_t n = 0;
    for (const char *p = base; *p && n + 1 < cap && n < 180; p++) {
        unsigned char c = (unsigned char)*p;
        out[n++] = (c < 0x20 || strchr("<>:\"|?*", c)) ? '_' : (char)c;
    }
    out[n] = 0;
    /* 去掉首尾的空格和点，防止 "." ".." 之类的名字 */
    while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '.'))
        out[--n] = 0;
    size_t lead = strspn(out, " .");
    if (lead)
        memmove(out, out + lead, strlen(out + lead) + 1);
    if (!out[0])
        snprintf(out, cap, "unnamed");
}

void unique_path(const char *dir, const char *name, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", dir, name);
    if (access(out, F_OK) != 0)
        return;
    char stem[256];
    const char *dot = strrchr(name, '.');
    size_t sl = dot && dot != name ? (size_t)(dot - name) : strlen(name);
    if (sl >= sizeof(stem))
        sl = sizeof(stem) - 1;
    memcpy(stem, name, sl);
    stem[sl] = 0;
    const char *ext = dot && dot != name ? dot : "";
    for (int i = 1; i < 10000; i++) {
        snprintf(out, cap, "%s/%s (%d)%s", dir, stem, i, ext);
        if (access(out, F_OK) != 0)
            return;
    }
}

int mkdir_p(const char *path)
{
    char tmp[MC_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    return (mkdir(tmp, 0755) == 0 || errno == EEXIST) ? 0 : -1;
}

/* ---------------- 发送方 ---------------- */

int outgoing_open(outgoing_file *o, const uint8_t fid[MC_ID_LEN], const char *path,
                  char *err, size_t errlen)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, errlen, "文件不存在或不是普通文件：%s", path);
        return -1;
    }
    memset(o, 0, sizeof(*o));
    o->fd = open(path, O_RDONLY);
    if (o->fd < 0) {
        snprintf(err, errlen, "无法打开文件：%s", strerror(errno));
        return -1;
    }
    o->used = 1;
    memcpy(o->fid, fid, MC_ID_LEN);
    snprintf(o->path, sizeof(o->path), "%s", path);
    const char *base = strrchr(path, '/');
    snprintf(o->name, sizeof(o->name), "%s", base ? base + 1 : path);
    o->size = (uint64_t)st.st_size;
    o->chunks = chunk_count(o->size);
    o->pending = calloc(o->chunks ? o->chunks : 1, 1);
    return 0;
}

ssize_t outgoing_read(outgoing_file *o, uint32_t index, uint8_t *buf)
{
    /* pread 不改变文件偏移，多个线程（首发与补发）可以同时读 */
    return pread(o->fd, buf, MC_CHUNK_DATA, (off_t)index * MC_CHUNK_DATA);
}

void outgoing_close(outgoing_file *o)
{
    if (o->fd >= 0)
        close(o->fd);
    free(o->pending);
    memset(o, 0, sizeof(*o));
    o->fd = -1;
}

/* ---------------- 接收方 ---------------- */

int incoming_open(incoming_file *f, const char *dir, char *err, size_t errlen)
{
    if (mkdir_p(dir) != 0) {
        snprintf(err, errlen, "无法创建下载目录 %s", dir);
        return -1;
    }
    snprintf(f->dir, sizeof(f->dir), "%s", dir);
    char partname[300];
    snprintf(partname, sizeof(partname), "%s.part", f->name);
    unique_path(dir, partname, f->part_path, sizeof(f->part_path));
    f->fd = open(f->part_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (f->fd < 0) {
        snprintf(err, errlen, "无法创建文件：%s", strerror(errno));
        return -1;
    }
    if (ftruncate(f->fd, (off_t)f->size) != 0) {
        snprintf(err, errlen, "磁盘空间不足");
        close(f->fd);
        unlink(f->part_path);
        return -1;
    }
    f->bitmap = calloc(f->chunks ? f->chunks : 1, 1);
    f->state = IN_RECEIVING;
    return 0;
}

int incoming_write(incoming_file *f, uint32_t index, const uint8_t *data, size_t len)
{
    if (f->state != IN_RECEIVING || index >= f->chunks)
        return 0;
    uint64_t off = (uint64_t)index * MC_CHUNK_DATA;
    size_t expected = (size_t)(f->size - off < MC_CHUNK_DATA ? f->size - off : MC_CHUNK_DATA);
    if (len != expected || f->bitmap[index])
        return 0;
    if (pwrite(f->fd, data, len, (off_t)off) != (ssize_t)len)
        return 0;
    f->bitmap[index] = 1;
    f->received++;
    return 1;
}

int incoming_finalize(incoming_file *f, char *reason, size_t cap)
{
    if (f->state != IN_RECEIVING)
        return f->state == IN_DONE;
    fsync(f->fd);
    close(f->fd);
    f->fd = -1;
    uint8_t h[32];
    if (sha256_file(f->part_path, h) != 0 || memcmp(h, f->sha, 32) != 0) {
        unlink(f->part_path);
        f->state = IN_FAILED;
        snprintf(reason, cap, "SHA-256 校验失败");
        return 0;
    }
    unique_path(f->dir, f->name, f->final_path, sizeof(f->final_path));
    if (rename(f->part_path, f->final_path) != 0) {
        f->state = IN_FAILED;
        snprintf(reason, cap, "保存文件失败：%s", strerror(errno));
        return 0;
    }
    f->state = IN_DONE;
    snprintf(reason, cap, "校验通过");
    return 1;
}

void incoming_fail(incoming_file *f)
{
    if (f->state != IN_RECEIVING)
        return;
    if (f->fd >= 0)
        close(f->fd);
    f->fd = -1;
    unlink(f->part_path);
    f->state = IN_FAILED;
}

void incoming_release(incoming_file *f)
{
    if (f->state == IN_RECEIVING)
        incoming_fail(f);
    free(f->bitmap);
    memset(f, 0, sizeof(*f));
    f->fd = -1;
}
