/*
 * crypto.h —— 基于 OpenSSL 3 的混合加密
 *
 *  1. 每个节点启动时生成 RSA-2048 密钥对，节点 ID = SHA-256(公钥 DER) 前 8 字节；
 *  2. 管理员生成 256 位 AES 组密钥，用成员公钥做 RSA-OAEP(SHA-256) 加密后分发；
 *  3. 聊天和文件分片用组密钥做 AES-256-GCM 加密（机密性 + 完整性）；
 *  4. 密钥分发、踢人报文由管理员用 RSA-PSS(SHA-256) 签名，防止伪造。
 */
#ifndef MC_CRYPTO_H
#define MC_CRYPTO_H

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

#define MC_KEY_LEN 32
#define MC_NONCE_LEN 12
#define MC_TAG_LEN 16
#define MC_GCM_OVERHEAD (MC_NONCE_LEN + MC_TAG_LEN)
#define MC_PUB_MAX 600
#define MC_RSA_BYTES 256

typedef struct {
    EVP_PKEY *pkey;
    uint8_t pub_der[MC_PUB_MAX];
    int pub_len;
    uint8_t id[MC_ID_LEN];
} identity;

int identity_generate(identity *idn);
void identity_free(identity *idn);

void node_id_of(const uint8_t *der, size_t len, uint8_t out[MC_ID_LEN]);
EVP_PKEY *pubkey_load(const uint8_t *der, size_t len); /* 失败返回 NULL */

/* RSA-OAEP 封装/解封 32 字节组密钥。成功返回 0 */
int rsa_wrap(EVP_PKEY *pub, const uint8_t key[MC_KEY_LEN], uint8_t *out, size_t *outlen);
int rsa_unwrap(identity *idn, const uint8_t *in, size_t inlen, uint8_t key[MC_KEY_LEN]);

/* RSA-PSS 签名/验签。sign 成功返回 0；verify 签名正确返回 1 */
int rsa_sign(identity *idn, const uint8_t *data, size_t len, uint8_t *sig, size_t *siglen);
int rsa_verify(EVP_PKEY *pub, const uint8_t *data, size_t len, const uint8_t *sig, size_t siglen);

/* AES-256-GCM。out 至少 ptlen + MC_GCM_OVERHEAD 字节。
 * seal 返回输出长度；open 返回明文长度；失败（含认证失败）返回 -1 */
int gcm_seal(const uint8_t key[MC_KEY_LEN], const uint8_t *pt, size_t ptlen,
             const uint8_t *aad, size_t aadlen, uint8_t *out);
int gcm_open(const uint8_t key[MC_KEY_LEN], const uint8_t *in, size_t inlen,
             const uint8_t *aad, size_t aadlen, uint8_t *out);

void random_bytes(void *buf, size_t n);
void sha256(const void *data, size_t len, uint8_t out[32]);
/* 计算文件 SHA-256，成功返回 0 */
int sha256_file(const char *path, uint8_t out[32]);
void hex_encode(const uint8_t *in, size_t n, char *out); /* out 至少 2n+1 */

#endif
