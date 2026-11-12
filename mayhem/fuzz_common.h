#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

/*
 * Two-buffer inputs are laid out as [selector:1][split:2 little-endian][A: split bytes][B: the rest].
 * Anything shorter than the 3-byte prefix, or a split past the end, is not a framed input.
 */
struct fuzz_input {
	uint8_t sel;
	const uint8_t *a;
	size_t a_size;
	const uint8_t *b;
	size_t b_size;
};

static inline int fuzz_split(const uint8_t *data, size_t size, struct fuzz_input *in)
{
	if (size < 3) {
		return -1;
	}
	size_t split = (size_t)data[1] | ((size_t)data[2] << 8);
	if (split > size - 3) {
		return -1;
	}
	in->sel = data[0];
	in->a = data + 3;
	in->a_size = split;
	in->b = data + 3 + split;
	in->b_size = size - 3 - split;
	return 0;
}

static void fuzz_discard_log(enum loglevel level, const char *fmt, va_list ap)
{
	(void)level;
	(void)fmt;
	(void)ap;
}

static inline void fuzz_quiet_logging(void)
{
	logger_set_print_func(fuzz_discard_log);
}

/* Heap copy so ASan sees the exact input size (the fuzzer's buffer is not exact-fit). */
static inline uint8_t *fuzz_dup(const uint8_t *p, size_t n)
{
	uint8_t *c = malloc(n ? n : 1);
	if (c && n) {
		memcpy(c, p, n);
	}
	return c;
}

#endif
