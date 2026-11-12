// Fuzzes ACE3 (USB-C controller) firmware assembly: ace3_create_binary reads a UARP superbinary (A) whose
// payload table is an NSKeyedArchive plist, and a TSS response plist (B) carrying the controller ticket.
#include <plist/plist.h>

#include "ace3.h"
#include "fuzz_common.h"

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

	plist_t tss = NULL;
	plist_from_memory((const char *)in.b, (uint32_t)in.b_size, &tss, NULL);
	if (!tss) {
		return -1;
	}

	uint8_t *uarp = fuzz_dup(in.a, in.a_size);
	void *out = NULL;
	size_t out_size = 0;
	/* Board ID and product revision select the payload; the selector exposes both axes. */
	int rc = ace3_create_binary(uarp, in.a_size, 0x10 + (in.sel & 0x0f), in.sel >> 4, tss, &out, &out_size);
	free(uarp);
	plist_free(tss);
	if (rc != 0) {
		return -1;
	}
	free(out);
	return 0;
}
