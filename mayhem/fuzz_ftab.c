// Fuzzes the ftab (firmware table) parser/writer: ftab_parse, ftab_get_entry_ptr, ftab_add_entry, ftab_write.
#include "fuzz_common.h"
#include "ftab.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	fuzz_quiet_logging();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *in = fuzz_dup(data, size);
	ftab_t ftab = NULL;
	uint32_t tag = 0;

	if (ftab_parse(in, size, &ftab, &tag) != 0) {
		free(in);
		return -1;
	}

	for (uint32_t i = 0; i < ftab->header.num_entries; i++) {
		void *p = NULL;
		size_t psize = 0;
		ftab_get_entry_ptr(ftab, ftab->entries[i].tag, &p, &psize);
	}

	void *out = NULL;
	size_t out_size = 0;
	if (ftab_write(ftab, &out, &out_size) == 0) {
		free(out);
	}

	if (ftab_add_entry(ftab, 0x74657374 /* 'test' */, in, size) == 0 && ftab_write(ftab, &out, &out_size) == 0) {
		free(out);
	}

	ftab_free(ftab);
	free(in);
	return 0;
}
