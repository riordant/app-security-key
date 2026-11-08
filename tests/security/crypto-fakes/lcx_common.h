/* NEW TEST-ONLY SHIM: SDK flag values; never part of a device build. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define CX_LAST 1
#define CX_ENCRYPT 4
#define CX_DECRYPT 0
#define CX_SIGN 6
#define CX_VERIFY 2
#define CX_CHAIN_ECB 0
#define CX_CHAIN_CBC 64
#define CX_CHAIN_CTR 128
#define CX_PAD_NONE 0
#define CX_PAD_ISO9797M1 8
#define CX_PAD_ISO9797M2 16
