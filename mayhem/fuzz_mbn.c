// Fuzzes baseband MBN stitching: mbn_stitch (v1/v2/BIN/ELF images) and mbn_mav25_stitch (ELF + v7 header blob).
#include "fuzz_common.h"
#include "mbn.h"

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

	uint8_t *image = fuzz_dup(in.a, in.a_size);
	uint8_t *blob = fuzz_dup(in.b, in.b_size);

	void *out = (in.sel & 1) ? mbn_mav25_stitch(image, in.a_size, blob, in.b_size)
	                         : mbn_stitch(image, in.a_size, blob, in.b_size);
	free(image);
	free(blob);
	if (!out) {
		return -1;
	}
	free(out);
	return 0;
}
