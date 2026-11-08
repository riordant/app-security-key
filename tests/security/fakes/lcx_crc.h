#pragma once
#include <stddef.h>
#include <stdint.h>
uint16_t cx_crc16_update(uint16_t crc, const void *data, size_t length);
