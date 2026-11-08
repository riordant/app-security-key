/* NEW TEST-ONLY SHIM: AES calls are supplied by OpenSSL, not new AES code. */
#pragma once
#include "cx_errors.h"
#include "decorators.h"
#include <stddef.h>
#include <stdint.h>
#define CX_AES_BLOCK_SIZE 16
typedef struct { unsigned int size; unsigned char keys[32]; } cx_aes_key_t;
cx_err_t cx_aes_init_key_no_throw(const uint8_t *, size_t, cx_aes_key_t *);
cx_err_t cx_aes_enc_block(const cx_aes_key_t *, const uint8_t *, uint8_t *);
cx_err_t cx_aes_dec_block(const cx_aes_key_t *, const uint8_t *, uint8_t *);
