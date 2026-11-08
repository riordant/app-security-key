/* @BANNER@ */

#ifdef HAVE_CMAC
#include "cx_utils.h"
#include "cx_ram.h"
#include "cx_cmac.h"
#include <string.h>

#define CMAC_CONSTANT_R_64  (0x1B)
#define CMAC_CONSTANT_R_128 (0x87)

cx_err_t cx_cmac_start(cx_cipher_context_t *ctx, const uint8_t *key, size_t key_bitlen)
{
    cx_err_t error;

    if ((NULL == ctx) || (NULL == key)) {
        return CX_INVALID_PARAMETER;
    }

    ctx->cmac_ctx = &G_cx.cmac;
    memset(ctx->cmac_ctx, 0, sizeof(cx_cmac_context_t));
    CX_CHECK(cx_cipher_setkey(ctx, key, key_bitlen, CX_ENCRYPT));

end:
    return error;
}

cx_err_t cx_cmac_update(cx_cipher_context_t *ctx, const uint8_t *input, size_t in_len)
{
    cx_err_t error;
    size_t   out_len;
    size_t   i, n;
    size_t  *current_len;

    if ((NULL == ctx) || (NULL == ctx->cipher_info) || (NULL == input) || (NULL == ctx->cmac_ctx)) {
        return CX_INVALID_PARAMETER;
    }
    if (ctx->cipher_info->block_size != CX_AES_BLOCK_SIZE ||
        ctx->cmac_ctx->unprocessed_len > CX_AES_BLOCK_SIZE || in_len > SIZE_MAX - CX_AES_BLOCK_SIZE)
        return CX_INVALID_PARAMETER_SIZE;
    out_len = ctx->cipher_info->block_size;

    current_len = &ctx->cmac_ctx->unprocessed_len;

    if ((*current_len > 0) && (in_len > ctx->cipher_info->block_size - *current_len)) {
        memcpy(ctx->cmac_ctx->unprocessed_block + *current_len,
               input,
               ctx->cipher_info->block_size - *current_len);
        cx_memxor(
            ctx->cmac_ctx->state, ctx->cmac_ctx->unprocessed_block, ctx->cipher_info->block_size);
        CX_CHECK(cx_cipher_update(ctx,
                                  ctx->cmac_ctx->state,
                                  ctx->cipher_info->block_size,
                                  ctx->cmac_ctx->state,
                                  &out_len));
        input += ctx->cipher_info->block_size - *current_len;
        in_len -= ctx->cipher_info->block_size - *current_len;
        *current_len = 0;
    }

    n = in_len / ctx->cipher_info->block_size + (in_len % ctx->cipher_info->block_size != 0);

    for (i = 1; i < n; i++) {
        cx_memxor(ctx->cmac_ctx->state, input, ctx->cipher_info->block_size);
        CX_CHECK(cx_cipher_update(ctx,
                                  ctx->cmac_ctx->state,
                                  ctx->cipher_info->block_size,
                                  ctx->cmac_ctx->state,
                                  &out_len));
        in_len -= ctx->cipher_info->block_size;
        input += ctx->cipher_info->block_size;
    }

    if (in_len > 0) {
        memcpy(ctx->cmac_ctx->unprocessed_block + *current_len, input, in_len);
        *current_len += in_len;
    }

    error = CX_OK;
end:
    return error;
}

cx_err_t cx_cmac_shift_and_xor(uint8_t *output, uint8_t *input, size_t block_size)
{
    uint8_t mask;
    uint8_t constant = 0x00;
    uint8_t msb      = 0x00;
    size_t  i;
    if (output == NULL || input == NULL) return CX_INVALID_PARAMETER;

    switch (block_size) {
#ifdef HAVE_AES
        case CX_AES_BLOCK_SIZE:
            constant = CMAC_CONSTANT_R_128;
            break;
#endif  // HAVE_AES
#ifdef HAVE_DES
        case CX_DES_BLOCK_SIZE:
            constant = CMAC_CONSTANT_R_64;
            break;
#endif  // HAVE_DES
        default:
            return CX_INVALID_PARAMETER_VALUE;
    }

    // Capture the original carry before an in-place doubling overwrites input[0].
    mask = -(input[0] >> 7);
    for (i = 0; i < block_size; i++) {
        uint8_t byte = input[block_size - 1 - i];
        output[block_size - 1 - i] = byte << 1 | msb;
        msb                        = byte >> 7;
    }

    output[block_size - 1] ^= constant & mask;

    return CX_OK;
}

static cx_err_t cx_cmac_generate_subkeys(cx_cipher_context_t *ctx,
                                         uint8_t             *sub_key1,
                                         uint8_t             *sub_key2)
{
    cx_err_t error;
    uint8_t  L[CMAC_MAX_BLOCK_LENGTH];
    size_t   out_len = ctx->cipher_info->block_size;

    memset(L, 0, CMAC_MAX_BLOCK_LENGTH);
    CX_CHECK(cx_cipher_update(ctx, L, ctx->cipher_info->block_size, L, &out_len));
    CX_CHECK(cx_cmac_shift_and_xor(sub_key1, L, ctx->cipher_info->block_size));
    CX_CHECK(cx_cmac_shift_and_xor(sub_key2, sub_key1, ctx->cipher_info->block_size));

end:
    explicit_bzero(L, sizeof(L));
    return error;
}

cx_err_t cx_cmac_finish(cx_cipher_context_t *ctx, uint8_t *output)
{
    uint8_t  sub_key1[CMAC_MAX_BLOCK_LENGTH];
    uint8_t  sub_key2[CMAC_MAX_BLOCK_LENGTH];
    uint8_t  last_block[CMAC_MAX_BLOCK_LENGTH];
    cx_err_t error;
    size_t   out_len;

    if ((NULL == ctx) || (NULL == ctx->cipher_info) || (NULL == ctx->cmac_ctx)
        || (NULL == output)) {
        return CX_INVALID_PARAMETER;
    }
    if (ctx->cipher_info->block_size != CX_AES_BLOCK_SIZE ||
        ctx->cmac_ctx->unprocessed_len > CX_AES_BLOCK_SIZE) return CX_INVALID_PARAMETER_SIZE;
    out_len = ctx->cipher_info->block_size;

    CX_CHECK(cx_cmac_generate_subkeys(ctx, sub_key1, sub_key2));

    if (ctx->cmac_ctx->unprocessed_len < ctx->cipher_info->block_size) {
        memcpy(last_block, ctx->cmac_ctx->unprocessed_block, ctx->cmac_ctx->unprocessed_len);
        add_one_and_zeros_padding(
            last_block, ctx->cipher_info->block_size, ctx->cmac_ctx->unprocessed_len);
        cx_memxor(last_block, sub_key2, ctx->cipher_info->block_size);
    }
    else {
        cx_memxor(ctx->cmac_ctx->unprocessed_block, sub_key1, ctx->cipher_info->block_size);
        memcpy(last_block, ctx->cmac_ctx->unprocessed_block, ctx->cipher_info->block_size);
    }

    cx_memxor(ctx->cmac_ctx->state, last_block, ctx->cipher_info->block_size);
    CX_CHECK(cx_cipher_update(
        ctx, ctx->cmac_ctx->state, ctx->cipher_info->block_size, ctx->cmac_ctx->state, &out_len));

    memcpy(output, ctx->cmac_ctx->state, ctx->cipher_info->block_size);

end:
    explicit_bzero(sub_key1, sizeof(sub_key1));
    explicit_bzero(sub_key2, sizeof(sub_key2));
    explicit_bzero(last_block, sizeof(last_block));
    explicit_bzero(ctx->cmac_ctx, sizeof(cx_cmac_context_t));
    return error;
}

cx_err_t cx_cmac(const cx_cipher_id_t type,
                 const uint8_t       *key,
                 size_t               key_bitlen,
                 const uint8_t       *input,
                 size_t               in_len,
                 uint8_t             *output)
{
    cx_cipher_context_t ctx;
    cx_err_t            error;
    cipher_key_t        key_ctx;

    if ((NULL == key) || (NULL == input) || (NULL == output)) {
        return CX_INVALID_PARAMETER;
    }
    CX_CHECK(cx_cipher_init(&ctx));
    ctx.cipher_key = &key_ctx;
    CX_CHECK(cx_cipher_setup(&ctx, type, CX_CHAIN_ECB));
    CX_CHECK(cx_cmac_start(&ctx, key, key_bitlen));
    CX_CHECK(cx_cmac_update(&ctx, input, in_len));
    CX_CHECK(cx_cmac_finish(&ctx, output));

end:
    if (ctx.cmac_ctx != NULL) explicit_bzero(ctx.cmac_ctx, sizeof(cx_cmac_context_t));
    explicit_bzero(&key_ctx, sizeof(key_ctx));
    explicit_bzero(&ctx, sizeof(ctx));
    return error;
}

#endif  // HAVE_CMAC
