/* NEW TEST-ONLY CODE: OpenSSL replaces the secure element's AES block service.
 * CMAC/SIV/cipher modes are the actual retained Security Key implementation.
 */
#include "cx_cipher.h"
#include "cx_utils.h"
#include "cx_ram.h"
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <string.h>
union cx_u G_cx;
static int fail_after = -1;
static size_t wipes;
void test_fail_after(int blocks) { fail_after=blocks; }
size_t test_wipe_calls(void) { return wipes; }
void explicit_bzero(void *value,size_t len) { OPENSSL_cleanse(value,len); wipes++; }
void test_fill_workspace(unsigned char value) { memset(&G_cx, value, sizeof(G_cx)); }
const void *test_workspace(void) { return &G_cx; }
size_t test_workspace_size(void) { return sizeof(G_cx); }
size_t test_cmac_size(void) { return sizeof(G_cx.cmac); }

cx_err_t cx_aes_init_key_no_throw(const uint8_t *raw, size_t size, cx_aes_key_t *key) {
    if (size != 16 && size != 24 && size != 32) return CX_INVALID_PARAMETER;
    key->size = size;
    memcpy(key->keys, raw, size);
    return CX_OK;
}
cx_err_t cx_aes_enc_block(const cx_aes_key_t *key, const uint8_t *in, uint8_t *out) {
    if(fail_after==0) return CX_INTERNAL_ERROR;
    if(fail_after>0) fail_after--;
    AES_KEY ctx;
    if (AES_set_encrypt_key(key->keys, key->size * 8, &ctx) != 0) return CX_INVALID_PARAMETER;
    AES_encrypt(in, out, &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    return CX_OK;
}
cx_err_t cx_aes_dec_block(const cx_aes_key_t *key, const uint8_t *in, uint8_t *out) {
    if(fail_after==0) return CX_INTERNAL_ERROR;
    if(fail_after>0) fail_after--;
    AES_KEY ctx;
    if (AES_set_decrypt_key(key->keys, key->size * 8, &ctx) != 0) return CX_INVALID_PARAMETER;
    AES_decrypt(in, out, &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    return CX_OK;
}
cx_err_t cx_aes_set_key_hw(const cx_aes_key_t *key, uint32_t mode) {
    (void)key; (void)mode; return CX_OK;
}
void cx_aes_reset_hw(void) {}
void cx_memxor(uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) a[i] ^= b[i];
}
