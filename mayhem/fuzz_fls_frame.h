#ifndef MAYHEM_FUZZ_FLS_FRAME_H
#define MAYHEM_FUZZ_FLS_FRAME_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * fuzz_fls feeds fls_parse() a container serialized from a list of element records
 * [kind:1][payload length:1][payload]. Each record becomes one FLS element: type (u32 LE), size (u32 LE,
 * = 8 + payload length), then the payload, which carries the element's `empty` field, its type-specific
 * header fields and its data. The element's own size field is always the byte count of the record, so every
 * element advances the parse cursor: fls_parse_elements() loops forever on a size-0 element, and a raw
 * mutation of a size field reaches that within a few executions. The remaining fields stay fuzzer-controlled.
 * A truncated record is not a framed input.
 *
 * kind 0/1/2 select the 0x0c/0x10/0x14 elements fls.c treats specially; kind k >= 3 is the generic element
 * of type k - 2.
 */
static inline uint32_t fuzz_fls_type(uint8_t kind)
{
	switch (kind) {
	case 0:
		return 0x0c;
	case 1:
		return 0x10;
	case 2:
		return 0x14;
	default:
		return (uint32_t)kind - 2;
	}
}

static inline uint8_t *fuzz_fls_build(const uint8_t *a, size_t n, size_t *out_size)
{
	size_t total = 0, i = 0;
	while (i < n) {
		if (n - i < 2 || (size_t)a[i + 1] > n - i - 2) {
			return NULL;
		}
		total += 8 + a[i + 1];
		i += 2 + a[i + 1];
	}
	if (total == 0) {
		return NULL;
	}

	uint8_t *out = malloc(total);
	if (!out) {
		return NULL;
	}
	size_t o = 0;
	for (i = 0; i < n; i += 2 + a[i + 1]) {
		uint32_t type = fuzz_fls_type(a[i]);
		uint32_t size = 8 + a[i + 1];
		memcpy(out + o, &type, 4);
		memcpy(out + o + 4, &size, 4);
		memcpy(out + o + 8, a + i + 2, a[i + 1]);
		o += size;
	}
	*out_size = total;
	return out;
}

#endif
