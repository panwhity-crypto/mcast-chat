/* 不需要网络的单元测试：报文编解码、加密、文件重组 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "filexfer.h"
#include "protocol.h"

static int failures, checks;
#define CHECK(c)                                                                    \
    do {                                                                            \
        checks++;                                                                   \
        if (!(c)) {                                                                 \
            failures++;                                                             \
            fprintf(stderr, "  失败 %s:%d: %s\n", __FILE__, __LINE__, #c);          \
        }                                                                           \
    } while (0)
#define RUN(fn) (printf("- %s\n", #fn), fn())

static void test_header_roundtrip(void)
{
    msg_header h = {.type = MT_CHAT, .seq = 42, .epoch = 7}, g;
    memcpy(h.sender, "12345678", 8);
    uint8_t buf[MC_HEADER_SIZE];
    hdr_pack(&h, buf);
    CHECK(buf[0] == 'M' && buf[1] == 'C' && buf[2] == MC_VERSION);
    CHECK(hdr_parse(buf, sizeof(buf), &g) == 0);
    CHECK(g.type == MT_CHAT && g.seq == 42 && g.epoch == 7 && memcmp(g.sender, "12345678", 8) == 0);
    buf[0] = 'X';
    CHECK(hdr_parse(buf, sizeof(buf), &g) != 0);   /* magic 不对 */
    CHECK(hdr_parse(buf, 5, &g) != 0);             /* 过短 */
    hdr_pack(&h, buf);
    buf[3] = 99;
    CHECK(hdr_parse(buf, sizeof(buf), &g) != 0);   /* 未知类型 */
}

static void test_buffers(void)
{
    uint8_t mem[8];
    wbuf w;
    wb_init(&w, mem, sizeof(mem));
    wb_u32(&w, 0x01020304);
    wb_u32(&w, 5);
    CHECK(!w.err && w.len == 8);
    wb_u8(&w, 1);
    CHECK(w.err); /* 写越界被拦截 */
    rbuf r;
    rb_init(&r, mem, 8);
    CHECK(rb_u32(&r) == 0x01020304 && rb_u32(&r) == 5 && !r.err);
    rb_u8(&r);
    CHECK(r.err); /* 读越界被拦截 */
    uint8_t s[4] = {0, 200, 'a', 'b'}; /* 声称 200 字节的字符串，实际只有 2 字节 */
    char out[16];
    rb_init(&r, s, 4);
    CHECK(rb_str16(&r, out, sizeof(out)) != 0 && r.err);
}

static void test_datagram_fits_mtu(void)
{
    int size = MC_HEADER_SIZE + MC_NONCE_LEN + MC_ID_LEN + 4 + MC_CHUNK_DATA + MC_TAG_LEN + 28;
    CHECK(size <= 1500);
}

static void test_gcm(void)
{
    uint8_t key[32], key2[32], hdr[MC_HEADER_SIZE] = {0}, out[64], pt[64];
    random_bytes(key, 32);
    random_bytes(key2, 32);
    int n = gcm_seal(key, (const uint8_t *)"hello", 5, hdr, sizeof(hdr), out);
    CHECK(n == 5 + MC_GCM_OVERHEAD);
    CHECK(gcm_open(key, out, (size_t)n, hdr, sizeof(hdr), pt) == 5 && memcmp(pt, "hello", 5) == 0);
    CHECK(gcm_open(key2, out, (size_t)n, hdr, sizeof(hdr), pt) < 0); /* 错误密钥 */
    hdr[5] ^= 1;
    CHECK(gcm_open(key, out, (size_t)n, hdr, sizeof(hdr), pt) < 0);  /* 头部被改 */
    hdr[5] ^= 1;
    out[n - 1] ^= 1;
    CHECK(gcm_open(key, out, (size_t)n, hdr, sizeof(hdr), pt) < 0);  /* 密文被改 */
}

static void test_rsa(void)
{
    identity a, b;
    CHECK(identity_generate(&a) == 0 && identity_generate(&b) == 0);
    EVP_PKEY *bpub = pubkey_load(b.pub_der, (size_t)b.pub_len);
    EVP_PKEY *apub = pubkey_load(a.pub_der, (size_t)a.pub_len);
    CHECK(bpub && apub);
    uint8_t key[32], got[32], enc[MC_RSA_BYTES];
    size_t elen;
    random_bytes(key, 32);
    CHECK(rsa_wrap(bpub, key, enc, &elen) == 0 && elen == 256);
    CHECK(rsa_unwrap(&b, enc, elen, got) == 0 && memcmp(key, got, 32) == 0);
    CHECK(rsa_unwrap(&a, enc, elen, got) != 0); /* 别人解不开 */

    uint8_t sig[MC_RSA_BYTES];
    size_t slen;
    CHECK(rsa_sign(&a, (const uint8_t *)"kick bob", 8, sig, &slen) == 0);
    CHECK(rsa_verify(apub, (const uint8_t *)"kick bob", 8, sig, slen) == 1);
    CHECK(rsa_verify(apub, (const uint8_t *)"kick ann", 8, sig, slen) == 0);
    CHECK(rsa_verify(bpub, (const uint8_t *)"kick bob", 8, sig, slen) == 0);

    uint8_t id[8];
    node_id_of(b.pub_der, (size_t)b.pub_len, id);
    CHECK(memcmp(id, b.id, 8) == 0);
    EVP_PKEY_free(apub);
    EVP_PKEY_free(bpub);
    identity_free(&a);
    identity_free(&b);
}

static void test_safe_filename(void)
{
    char out[256];
    safe_filename("../../etc/passwd", out, sizeof(out));
    CHECK(strcmp(out, "passwd") == 0);
    safe_filename("..\\..\\a.mp3", out, sizeof(out));
    CHECK(strcmp(out, "a.mp3") == 0);
    safe_filename("..", out, sizeof(out));
    CHECK(strcmp(out, "unnamed") == 0);
    safe_filename("", out, sizeof(out));
    CHECK(strcmp(out, "unnamed") == 0);
    CHECK(is_media_file("a.MP4") && is_media_file("b.wav") && !is_media_file("c.txt"));
}

static void make_file(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    uint8_t *b = malloc(size);
    random_bytes(b, size);
    fwrite(b, 1, size, f);
    fclose(f);
    free(b);
}

static int files_equal(const char *a, const char *b)
{
    uint8_t ha[32], hb[32];
    return sha256_file(a, ha) == 0 && sha256_file(b, hb) == 0 && memcmp(ha, hb, 32) == 0;
}

static void test_reassembly(int corrupt_hash)
{
    char dir[] = "/tmp/mc_unit_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char src[300], dl[300];
    snprintf(src, sizeof(src), "%s/src.bin", dir);
    snprintf(dl, sizeof(dl), "%s/dl", dir);
    make_file(src, 5000);

    outgoing_file o;
    char err[160];
    uint8_t fid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(outgoing_open(&o, fid, src, err, sizeof(err)) == 0);
    sha256_file(src, o.sha);
    CHECK(o.chunks == 5);

    incoming_file f;
    memset(&f, 0, sizeof(f));
    memcpy(f.fid, fid, 8);
    snprintf(f.name, sizeof(f.name), "src.bin");
    f.size = o.size;
    f.chunks = o.chunks;
    memcpy(f.sha, o.sha, 32);
    if (corrupt_hash)
        f.sha[0] ^= 1;
    CHECK(incoming_open(&f, dl, err, sizeof(err)) == 0);
    uint8_t buf[MC_CHUNK_DATA];
    for (int i = (int)o.chunks - 1; i >= 0; i--) { /* 逆序到达 */
        ssize_t r = outgoing_read(&o, (uint32_t)i, buf);
        CHECK(incoming_write(&f, (uint32_t)i, buf, (size_t)r) == 1);
    }
    ssize_t r = outgoing_read(&o, 0, buf);
    CHECK(incoming_write(&f, 0, buf, (size_t)r) == 0);  /* 重复分片 */
    CHECK(incoming_write(&f, 99, buf, (size_t)r) == 0); /* 越界分片 */
    CHECK(f.received == f.chunks);
    char reason[160];
    int ok = incoming_finalize(&f, reason, sizeof(reason));
    if (corrupt_hash) {
        CHECK(!ok && strstr(reason, "校验"));
        CHECK(access(f.part_path, F_OK) != 0); /* 校验失败的残留文件被删掉 */
    } else {
        CHECK(ok && files_equal(src, f.final_path));
    }
    incoming_release(&f);
    outgoing_close(&o);
    char cmd[400];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    CHECK(system(cmd) == 0);
}

static void test_reassembly_ok(void) { test_reassembly(0); }
static void test_reassembly_bad_hash(void) { test_reassembly(1); }

int main(void)
{
    printf("== 单元测试\n");
    RUN(test_header_roundtrip);
    RUN(test_buffers);
    RUN(test_datagram_fits_mtu);
    RUN(test_gcm);
    RUN(test_rsa);
    RUN(test_safe_filename);
    RUN(test_reassembly_ok);
    RUN(test_reassembly_bad_hash);
    printf("单元测试：%d 项检查，%d 项失败\n", checks, failures);
    return failures ? 1 : 0;
}
