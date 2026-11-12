// Fuzzes IMG4 personalization. Selector bit 7 clear: img4_stitch_component takes an IM4P component (A) and a
// TSS response plist (B, any libplist format) carrying the ApImg4Ticket; bit 6 sets whether the build parameters
// request a nonce slot and the low bits pick the component name, so the SEP/LLB/anid/snid and *-TBM paths are
// reachable. Bit 7 set: img4_create_local_manifest builds an IM4M from a TSS request plist (A) and a build
// identity plist (B; an empty B is the library's "no build identity" case).
#include <plist/plist.h>

#include "fuzz_common.h"
#include "img4.h"

static const char *const components[] = {
	"iBSS", "RestoreKernelCache", "RestoreDeviceTree", "RestoreSEP", "RestoreLogo", "RestoreTrustCache",
	"Ap,RestoreSecureM3Firmware", "SEP", "SepStage1", "LLB", "RestoreDCP", "Ap,RestorecL4",
};

static int fuzz_local_manifest(const struct fuzz_input *in)
{
	plist_t request = NULL;
	plist_from_memory((const char *)in->a, (uint32_t)in->a_size, &request, NULL);
	if (!request) {
		return -1;
	}
	plist_t identity = NULL;
	if (in->b_size) {
		plist_from_memory((const char *)in->b, (uint32_t)in->b_size, &identity, NULL);
		if (!identity) {
			plist_free(request);
			return -1;
		}
	}

	plist_t manifest = NULL;
	int rc = img4_create_local_manifest(request, identity, &manifest);
	plist_free(request);
	plist_free(identity);
	if (rc != 0) {
		return -1;
	}
	plist_free(manifest);
	return 0;
}

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

	if (in.sel & 0x80) {
		return fuzz_local_manifest(&in);
	}

	plist_t tss = NULL;
	plist_from_memory((const char *)in.b, (uint32_t)in.b_size, &tss, NULL);
	if (!tss) {
		return -1;
	}

	plist_t params = plist_new_dict();
	plist_dict_set_item(params, "RequiresNonceSlot", plist_new_bool((in.sel >> 6) & 1));
	const char *name = components[(in.sel & 0x3f) % (sizeof(components) / sizeof(components[0]))];

	uint8_t *component = fuzz_dup(in.a, in.a_size);
	void *out = NULL;
	size_t out_size = 0;
	int rc = img4_stitch_component(name, component, in.a_size, params, tss, &out, &out_size);
	free(component);
	plist_free(params);
	plist_free(tss);
	if (rc != 0) {
		return -1;
	}
	free(out);
	return 0;
}
