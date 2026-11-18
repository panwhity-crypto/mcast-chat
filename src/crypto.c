#include "crypto.h"

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int identity_generate(identity *idn)
{
    memset(idn, 0, sizeof(*idn));
    idn->pkey = EVP_RSA_gen(2048);
    if (!idn->pkey)
        return -1;
    unsigned char *p = idn->pub_der;
    int n = i2d_PUBKEY(idn->pkey, NULL);
    if (n <= 0 || n > MC_PUB_MAX)
        return -1;
    idn->pub_len = i2d_PUBKEY(idn->pkey, &p);
    node_id_of(idn->pub_der, (size_t)idn->pub_len, idn->id);
    return 0;
}

void identity_free(identity *idn)
{
    EVP_PKEY_free(idn->pkey);
    idn->pkey = NULL;
}

void node_id_of(const uint8_t *der, size_t len, uint8_t out[MC_ID_LEN])
{
    uint8_t h[32];
    sha256(der, len, h);
    memcpy(out, h, MC_ID_LEN);
}

EVP_PKEY *pubkey_load(const uint8_t *der, size_t len)
{
    const unsigned char *p = der;
    EVP_PKEY *k = d2i_PUBKEY(NULL, &p, (long)len);
    if (k && EVP_PKEY_get_base_id(k) != EVP_PKEY_RSA) {
        EVP_PKEY_free(k);
        return NULL;
    }
    return k;
}

int rsa_wrap(EVP_PKEY *pub, const uint8_t key[MC_KEY_LEN], uint8_t *out, size_t *outlen)
{
    int ok = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    if (ctx && EVP_PKEY_encrypt_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0) {
        size_t n = MC_RSA_BYTES;
        if (EVP_PKEY_encrypt(ctx, out, &n, key, MC_KEY_LEN) > 0) {
            *outlen = n;
            ok = 0;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int rsa_unwrap(identity *idn, const uint8_t *in, size_t inlen, uint8_t key[MC_KEY_LEN])
{
    int ok = -1;
    uint8_t buf[MC_RSA_BYTES];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(idn->pkey, NULL);
    if (ctx && EVP_PKEY_decrypt_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0) {
        size_t n = sizeof(buf);
        if (EVP_PKEY_decrypt(ctx, buf, &n, in, inlen) > 0 && n == MC_KEY_LEN) {
            memcpy(key, buf, MC_KEY_LEN);
            ok = 0;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int rsa_sign(identity *idn, const uint8_t *data, size_t len, uint8_t *sig, size_t *siglen)
{
    int ok = -1;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md && EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, idn->pkey) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0) {
        size_t n = MC_RSA_BYTES;
        if (EVP_DigestSign(md, sig, &n, data, len) > 0) {
            *siglen = n;
            ok = 0;
        }
    }
    EVP_MD_CTX_free(md);
    return ok;
}

int rsa_verify(EVP_PKEY *pub, const uint8_t *data, size_t len, const uint8_t *sig, size_t siglen)
{
    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md && EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), NULL, pub) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0) {
        ok = EVP_DigestVerify(md, sig, siglen, data, len) == 1;
    }
    EVP_MD_CTX_free(md);
    return ok;
}

int gcm_seal(const uint8_t key[MC_KEY_LEN], const uint8_t *pt, size_t ptlen,
             const uint8_t *aad, size_t aadlen, uint8_t *out)
{
    int len, total = -1;
    uint8_t *nonce = out, *ct = out + MC_NONCE_LEN;
    random_bytes(nonce, MC_NONCE_LEN); /* 96 位随机 nonce */
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c && EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, nonce) > 0 &&
        EVP_EncryptUpdate(c, NULL, &len, aad, (int)aadlen) > 0 &&
        EVP_EncryptUpdate(c, ct, &len, pt, (int)ptlen) > 0) {
        int n = len;
        if (EVP_EncryptFinal_ex(c, ct + n, &len) > 0) {
            n += len;
            if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, MC_TAG_LEN, ct + n) > 0)
                total = MC_NONCE_LEN + n + MC_TAG_LEN;
        }
    }
    EVP_CIPHER_CTX_free(c);
    return total;
}

int gcm_open(const uint8_t key[MC_KEY_LEN], const uint8_t *in, size_t inlen,
             const uint8_t *aad, size_t aadlen, uint8_t *out)
{
    if (inlen < MC_GCM_OVERHEAD)
        return -1;
    const uint8_t *nonce = in, *ct = in + MC_NONCE_LEN;
    int ctlen = (int)(inlen - MC_GCM_OVERHEAD), len, result = -1;
    uint8_t tag[MC_TAG_LEN];
    memcpy(tag, in + inlen - MC_TAG_LEN, MC_TAG_LEN);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c && EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, nonce) > 0 &&
        EVP_DecryptUpdate(c, NULL, &len, aad, (int)aadlen) > 0 &&
        EVP_DecryptUpdate(c, out, &len, ct, ctlen) > 0) {
        int n = len;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, MC_TAG_LEN, tag) > 0 &&
            EVP_DecryptFinal_ex(c, out + n, &len) > 0) /* tag 校验失败时返回 0 */
            result = n + len;
    }
    EVP_CIPHER_CTX_free(c);
    return result;
}

void random_bytes(void *buf, size_t n)
{
    if (RAND_bytes(buf, (int)n) != 1) {
        fprintf(stderr, "RAND_bytes 失败\n");
        abort();
    }
}

void sha256(const void *data, size_t len, uint8_t out[32])
{
    unsigned int n = 32;
    EVP_Digest(data, len, out, &n, EVP_sha256(), NULL);
}

int sha256_file(const char *path, uint8_t out[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), NULL);
    static __thread uint8_t buf[1 << 16];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        EVP_DigestUpdate(md, buf, n);
    int err = ferror(f);
    fclose(f);
    unsigned int len = 32;
    EVP_DigestFinal_ex(md, out, &len);
    EVP_MD_CTX_free(md);
    return err ? -1 : 0;
}

void hex_encode(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", in[i]);
    out[2 * n] = 0;
}
