/* NEW TEST-ONLY SHIM. */
#pragma once
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define UPPER_ALIGN(value, alignment, type) (((type)(value) + (type)(alignment) - 1) & ~((type)(alignment) - 1))
