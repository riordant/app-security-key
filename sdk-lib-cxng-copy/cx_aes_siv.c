/* @BANNER@ */

#ifdef HAVE_AES_SIV
#if defined(HAVE_AES) && defined(HAVE_CMAC)
#include "cx_cmac.h"
#include "cx_utils.h"
#include "lcx_cmac.h"
#include "lcx_aes_siv.h"
#include <stdbool.h>

uint8_t cx_constant_time_eq(const uint8_t *buf1, const uint8_t *buf2, size_t len);

static void cx_clear_bits(uint8_t *input)
{
    input[8] &= 0x7f;
    input[12] &= 0x7f;
}

cx_err_t cx_aes_siv_init(cx_aes_siv_context_t *ctx)
{
    if (ctx == NULL || ctx->cipher_ctx == NULL) return CX_INVALID_PARAMETER;
    explicit_bzero(ctx->key1, sizeof(ctx->key1));
    explicit_bzero(ctx->key2, sizeof(ctx->key2));
    explicit_bzero(ctx->tag_state, sizeof(ctx->tag_state));
    ctx->key_len = 0;
    ctx->mode = 0;
    cx_err_t error;
    CX_CHECK(cx_cipher_init(ctx->cipher_ctx));

end:
    return error;
}

cx_err_t cx_aes_siv_set_key(cx_aes_siv_context_t *ctx, const uint8_t *key, size_t key_bitlen)
{
    // AES SIV uses two keys of either 128, 192 or 256 bits each
    if (ctx == NULL || key == NULL || ctx->cipher_ctx == NULL ||
        ctx->cipher_ctx->cipher_key == NULL) return CX_INVALID_PARAMETER;
    if ((key_bitlen != 256 && key_bitlen != 384 && key_bitlen != 512) ||
        (ctx->cipher_type != (key_bitlen == 256 ? CX_CIPHER_AES_128 :
                             key_bitlen == 384 ? CX_CIPHER_AES_192 : CX_CIPHER_AES_256))) {
        return CX_INVALID_PARAMETER_SIZE;
    }

    ctx->key_len = key_bitlen / 2;
    memcpy(ctx->key1, key, ctx->key_len / 8);
    memcpy(ctx->key2, key + ctx->key_len / 8, ctx->key_len / 8);
    return CX_OK;
}

static bool siv_ready(const cx_aes_siv_context_t *ctx)
{
    return ctx != NULL && ctx->cipher_ctx != NULL && ctx->cipher_ctx->cipher_key != NULL &&
           ((ctx->key_len == 128 && ctx->cipher_type == CX_CIPHER_AES_128) ||
            (ctx->key_len == 192 && ctx->cipher_type == CX_CIPHER_AES_192) ||
            (ctx->key_len == 256 && ctx->cipher_type == CX_CIPHER_AES_256));
}

static void siv_clear_cmac(cx_aes_siv_context_t *ctx)
{
    if (ctx != NULL && ctx->cipher_ctx != NULL && ctx->cipher_ctx->cmac_ctx != NULL)
        explicit_bzero(ctx->cipher_ctx->cmac_ctx, sizeof(cx_cmac_context_t));
}

cx_err_t cx_aes_siv_start(cx_aes_siv_context_t *ctx,
                          uint32_t              mode,
                          const uint8_t        *iv,
                          size_t                iv_len)
{
    uint8_t  iv_used[CX_AES_BLOCK_SIZE] = {0};
    cx_err_t error;

    if (!siv_ready(ctx)) return CX_INVALID_PARAMETER;
    if ((mode != CX_ENCRYPT && mode != CX_DECRYPT) ||
        (mode == CX_DECRYPT && (iv == NULL || iv_len != CX_AES_BLOCK_SIZE)) ||
        (mode == CX_ENCRYPT && (iv != NULL || iv_len != 0)))
        return CX_INVALID_PARAMETER_VALUE;

    // Set up cipher to be used for CMAC computation
    CX_CHECK(cx_cipher_setup(ctx->cipher_ctx, ctx->cipher_type, CX_CHAIN_ECB));
    CX_CHECK(cx_cmac_start(ctx->cipher_ctx, ctx->key1, ctx->key_len));
    CX_CHECK(cx_cmac_update(ctx->cipher_ctx, iv_used, CX_AES_BLOCK_SIZE));
    CX_CHECK(cx_cmac_finish(ctx->cipher_ctx, ctx->tag_state));

    if (CX_DECRYPT == mode) {
        // Prepare for the AES-CTR computation
        memcpy(iv_used, iv, iv_len);
        cx_clear_bits(iv_used);
        CX_CHECK(cx_cipher_setup(ctx->cipher_ctx, ctx->cipher_type, CX_CHAIN_CTR));
        CX_CHECK(cx_cipher_setkey(ctx->cipher_ctx, ctx->key2, ctx->key_len, CX_ENCRYPT));
        CX_CHECK(cx_cipher_setiv(ctx->cipher_ctx, iv_used, CX_AES_BLOCK_SIZE));
    }
    ctx->mode = mode;

end:
    explicit_bzero(iv_used, sizeof(iv_used));
    return error;
}

cx_err_t cx_aes_siv_update_aad(cx_aes_siv_context_t *ctx, const uint8_t *aad, size_t aad_len)
{
    uint8_t  tmp[CX_AES_BLOCK_SIZE] = {0};
    cx_err_t error;

    if (!siv_ready(ctx)) return CX_INVALID_PARAMETER;
    if (NULL == aad) return aad_len == 0 ? CX_OK : CX_INVALID_PARAMETER;

    CX_CHECK(cx_cipher_setup(ctx->cipher_ctx, ctx->cipher_type, CX_CHAIN_ECB));
    CX_CHECK(cx_cmac_shift_and_xor(tmp, ctx->tag_state, CX_AES_BLOCK_SIZE));
    CX_CHECK(cx_cmac_start(ctx->cipher_ctx, ctx->key1, ctx->key_len));
    CX_CHECK(cx_cmac_update(ctx->cipher_ctx, aad, aad_len));
    CX_CHECK(cx_cmac_finish(ctx->cipher_ctx, ctx->tag_state));
    cx_memxor(ctx->tag_state, tmp, CX_AES_BLOCK_SIZE);

end:
    explicit_bzero(tmp, sizeof(tmp));
    return error;
}

cx_err_t cx_aes_siv_update(cx_aes_siv_context_t *ctx,
                           const uint8_t        *input,
                           uint8_t              *output,
                           size_t                len)
{
    size_t   out_len = len;
    cx_err_t error;
    if (!siv_ready(ctx) || input == NULL || output == NULL) return CX_INVALID_PARAMETER;
    CX_CHECK(cx_cipher_update(ctx->cipher_ctx, input, len, output, &out_len));
end:
    cx_cipher_reset(ctx->cipher_ctx);
    return error;
}

static cx_err_t cx_aes_siv_check_tag(cx_aes_siv_context_t *ctx, const uint8_t *tag)
{
    uint8_t diff;
    diff = cx_constant_time_eq(tag, ctx->tag_state, CX_AES_BLOCK_SIZE);
    return diff * CX_INVALID_PARAMETER_VALUE + (1 - diff) * CX_OK;
}

cx_err_t cx_aes_siv_finish(cx_aes_siv_context_t *ctx,
                           const uint8_t        *input,
                           size_t                in_len,
                           uint8_t              *tag)
{
    uint8_t  tmp[CX_AES_BLOCK_SIZE] = {0};
    cx_err_t error;

    if (!siv_ready(ctx) || tag == NULL || (input == NULL && in_len != 0))
        return CX_INVALID_PARAMETER;
    if (input == NULL) input = tmp; // empty plaintext, no NULL zero-length copy

    CX_CHECK(cx_cipher_setup(ctx->cipher_ctx, ctx->cipher_type, CX_CHAIN_ECB));
    if (in_len < CX_AES_BLOCK_SIZE) {
        CX_CHECK(cx_cmac_shift_and_xor(tmp, ctx->tag_state, CX_AES_BLOCK_SIZE));
        memset(ctx->tag_state, 0, CX_AES_BLOCK_SIZE);
        memcpy(ctx->tag_state, input, in_len);
        add_one_and_zeros_padding(ctx->tag_state, CX_AES_BLOCK_SIZE, in_len);
        cx_memxor(tmp, ctx->tag_state, CX_AES_BLOCK_SIZE);
        CX_CHECK(cx_cmac_start(ctx->cipher_ctx, ctx->key1, ctx->key_len));
        CX_CHECK(cx_cmac_update(ctx->cipher_ctx, tmp, CX_AES_BLOCK_SIZE));
        CX_CHECK(cx_cmac_finish(ctx->cipher_ctx, ctx->tag_state));
    }
    else {
        CX_CHECK(cx_cmac_start(ctx->cipher_ctx, ctx->key1, ctx->key_len));
        CX_CHECK(cx_cmac_update(ctx->cipher_ctx, input, in_len - CX_AES_BLOCK_SIZE));
        cx_memxor(ctx->tag_state, input + in_len - CX_AES_BLOCK_SIZE, CX_AES_BLOCK_SIZE);
        CX_CHECK(cx_cmac_update(ctx->cipher_ctx, ctx->tag_state, CX_AES_BLOCK_SIZE));
        CX_CHECK(cx_cmac_finish(ctx->cipher_ctx, ctx->tag_state));
    }
    if (CX_DECRYPT == ctx->mode) {
        error = cx_aes_siv_check_tag(ctx, tag);
        goto end;
    }
    memcpy(tag, ctx->tag_state, CX_AES_BLOCK_SIZE);
    // Prepare for the AES-CTR computation
    cx_clear_bits(ctx->tag_state);
    CX_CHECK(cx_cipher_setup(ctx->cipher_ctx, ctx->cipher_type, CX_CHAIN_CTR));
    CX_CHECK(cx_cipher_setkey(ctx->cipher_ctx, ctx->key2, ctx->key_len, CX_ENCRYPT));
    CX_CHECK(cx_cipher_setiv(ctx->cipher_ctx, ctx->tag_state, CX_AES_BLOCK_SIZE));

end:
    explicit_bzero(tmp, sizeof(tmp));
    return error;
}

static bool overlap(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return alen && blen && (x <= y ? y - x < alen : x - y < blen);
}

static bool siv_buffers_valid(const uint8_t *input, size_t len, const uint8_t *aad,
                              size_t aad_len, uint8_t *output, uint8_t *tag)
{
    if (tag == NULL || (len && (input == NULL || output == NULL)) ||
        (aad_len && aad == NULL) || len > SIZE_MAX - CX_AES_BLOCK_SIZE ||
        aad_len > SIZE_MAX - CX_AES_BLOCK_SIZE) return false;
    if (input != output && overlap(input,len,output,len)) return false;
    return !overlap(tag,CX_AES_BLOCK_SIZE,input,len) &&
           !overlap(tag,CX_AES_BLOCK_SIZE,output,len) && !overlap(aad,aad_len,output,len);
}

cx_err_t cx_aes_siv_encrypt(cx_aes_siv_context_t *ctx,
                            const uint8_t        *input,
                            size_t                in_len,
                            const uint8_t        *aad,
                            size_t                aad_len,
                            uint8_t              *output,
                            uint8_t              *tag)
{
    cx_err_t error;
    uint8_t empty = 0;
    if (!siv_ready(ctx) || !siv_buffers_valid(input,in_len,aad,aad_len,output,tag))
        return CX_INVALID_PARAMETER;
    if (input == NULL) input = &empty;
    if (output == NULL) output = &empty;
    CX_CHECK(cx_aes_siv_start(ctx, CX_ENCRYPT, NULL, 0));
    CX_CHECK(cx_aes_siv_update_aad(ctx, aad, aad_len));
    CX_CHECK(cx_aes_siv_finish(ctx, input, in_len, tag));
    CX_CHECK(cx_aes_siv_update(ctx, input, output, in_len));
end:
    if (error != CX_OK) {
        explicit_bzero(output, in_len);
        explicit_bzero(tag, CX_AES_BLOCK_SIZE);
    }
    siv_clear_cmac(ctx);
    return error;
}

cx_err_t cx_aes_siv_decrypt(cx_aes_siv_context_t *ctx,
                            const uint8_t        *input,
                            size_t                in_len,
                            const uint8_t        *aad,
                            size_t                aad_len,
                            uint8_t              *output,
                            uint8_t              *tag)
{
    cx_err_t error;
    uint8_t empty = 0;
    if (!siv_ready(ctx) || !siv_buffers_valid(input,in_len,aad,aad_len,output,tag))
        return CX_INVALID_PARAMETER;
    if (input == NULL) input = &empty;
    if (output == NULL) output = &empty;
    CX_CHECK(cx_aes_siv_start(ctx, CX_DECRYPT, tag, CX_AES_BLOCK_SIZE));
    CX_CHECK(cx_aes_siv_update(ctx, input, output, in_len));
    CX_CHECK(cx_aes_siv_update_aad(ctx, aad, aad_len));
    CX_CHECK(cx_aes_siv_finish(ctx, output, in_len, tag));

end:
    if (error != CX_OK) explicit_bzero(output, in_len);
    siv_clear_cmac(ctx);
    return error;
}

#endif  // HAVE_AES && HAVE_CMAC
#endif  // HAVE_AES_SIV
