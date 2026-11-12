// Fuzzes IMG3 personalization: img3_stitch_component parses component A as an IMG3 file and splices in
// the ECID/SHSH/CERT signature blob B.
//
// Caller contract (idevicerestore.c, img3 personalization): the blob buffer holds the whole ECID/SHSH/CERT
// sequence and `blob_size` is only the first (ECID) element's size, which img3_stitch_component requires to equal
// that element's full_size field. img3_replace_signature then reads the SHSH/CERT elements past blob_size, so the
// buffer must be larger. B stays whole in the heap buffer; blob_size is B's first-element full_size when B
// declares one that fits in B, else B's size (which takes the library's own size-mismatch rejection).
#include "fuzz_common.h"
#include "img3.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	fuzz_quiet_logging();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_input in;
	if (fuzz_split(data, size, &in) != 0) {
		return -1;
	}

	uint8_t *component = fuzz_dup(in.a, in.a_size);
	uint8_t *blob = fuzz_dup(in.b, in.b_size);
	void *out = NULL;
	size_t out_size = 0;

	size_t blob_size = in.b_size;
	if (in.b_size >= 8) {
		uint32_t first_full_size;
		memcpy(&first_full_size, in.b + 4, sizeof(first_full_size));
		if (first_full_size != 0 && first_full_size <= in.b_size) {
			blob_size = first_full_size;
		}
	}

	int rc = img3_stitch_component("iBSS", component, in.a_size, blob, blob_size, &out, &out_size);
	free(component);
	free(blob);
	if (rc != 0) {
		return -1;
	}
	free(out);
	return 0;
}
