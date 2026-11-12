// Fuzzes the baseband FLS container: fls_parse on a container serialized from input A's element records
// (fuzz_fls_frame.h), then fls_update_sig_blob / fls_insert_ticket with B.
#include "fuzz_common.h"
#include "fuzz_fls_frame.h"
#include "fls.h"

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

	size_t raw_size = 0;
	uint8_t *raw = fuzz_fls_build(in.a, in.a_size, &raw_size);
	if (!raw) {
		return -1;
	}
	fls_file *fls = fls_parse(raw, raw_size);
	free(raw);
	if (!fls) {
		return -1;
	}

	if (in.sel & 1) {
		fls_update_sig_blob(fls, in.b, in.b_size);
	} else {
		fls_insert_ticket(fls, in.b, in.b_size);
	}

	fls_free(fls);
	return 0;
}
