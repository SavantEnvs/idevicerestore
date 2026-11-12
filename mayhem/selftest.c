// Known-answer tests for the idevicerestore firmware parsers/stitchers, run by mayhem/test.sh.
// Usage: idevicerestore_selftest <repo root>   (fixtures are the committed seeds under mayhem/<target>/testsuite/)
#define _GNU_SOURCE
#include <zlib.h>
#include <plist/plist.h>

#include "fuzz_common.h"
#include "fuzz_fls_frame.h"
#include "ace3.h"
#include "fls.h"
#include "ftab.h"
#include "img3.h"
#include "img4.h"
#include "ipsw.h"
#include "mbn.h"

/* CRC-32 of the full expected outputs (sizes are asserted separately). */
#define FTAB_GOLDEN_CRC 0x42fea01au
#define FLS_UPDATE_GOLDEN_CRC 0x0edac1ccu
#define FLS_INSERT_GOLDEN_CRC 0x8b9a9cffu
#define IMG4_GOLDEN_CRC 0x9f3cfac0u
#define IMG4_MANIFEST_GOLDEN_SIZE 529
#define IMG4_MANIFEST_GOLDEN_CRC 0xd675fad3u
#define ACE3_GOLDEN_CRC 0xd3d19245u

static int passed, failed;
static const char *root;

#define CHECK(cond, ...)                                                       \
	do {                                                                       \
		if (cond) {                                                            \
			passed++;                                                          \
		} else {                                                               \
			failed++;                                                          \
			fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
			fprintf(stderr, __VA_ARGS__);                                      \
			fprintf(stderr, "\n");                                             \
		}                                                                      \
	} while (0)

#define CHECK_CRC(label, buf, len, want_len, want_crc)                         \
	do {                                                                       \
		uint32_t got_ = (uint32_t)crc32(0, (const Bytef *)(buf), (uInt)(len)); \
		CHECK((len) == (want_len) && got_ == (want_crc),                       \
		      "%s: size %zu crc %08x, want size %zu crc %08x", label,          \
		      (size_t)(len), got_, (size_t)(want_len), (uint32_t)(want_crc));  \
	} while (0)

static uint8_t *load(const char *rel, size_t *size)
{
	char path[1024];
	snprintf(path, sizeof(path), "%s/mayhem/%s", root, rel);
	FILE *f = fopen(path, "rb");
	if (!f) {
		failed++;
		fprintf(stderr, "FAIL: missing fixture %s\n", path);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	rewind(f);
	uint8_t *buf = malloc(n ? n : 1);
	if (fread(buf, 1, n, f) != (size_t)n) {
		failed++;
		fprintf(stderr, "FAIL: short read of %s\n", path);
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*size = n;
	return buf;
}

static int load_framed(const char *rel, uint8_t **raw, struct fuzz_input *in)
{
	size_t n;
	*raw = load(rel, &n);
	if (!*raw || fuzz_split(*raw, n, in) != 0) {
		failed++;
		fprintf(stderr, "FAIL: bad framed fixture %s\n", rel);
		return -1;
	}
	return 0;
}

static void test_ftab(void)
{
	size_t n;
	uint8_t *img = load("fuzz_ftab/testsuite/two_entries", &n);
	if (!img) {
		return;
	}
	ftab_t ft = NULL;
	uint32_t tag = 0;
	CHECK(ftab_parse(img, n, &ft, &tag) == 0, "ftab_parse failed");
	if (!ft) {
		free(img);
		return;
	}
	CHECK(tag == 0x726b6f73, "ftab tag %08x, want 'rkos'", tag);
	CHECK(ft->header.num_entries == 2, "ftab entries %u, want 2", ft->header.num_entries);

	void *p = NULL;
	size_t ps = 0;
	CHECK(ftab_get_entry_ptr(ft, 0x726b6173, &p, &ps) == 0 && ps == 20, "rkas size %zu, want 20", ps);
	CHECK(p && memcmp(p, "AAAAAAAAAAAAAAAAAAAA", 20) == 0, "rkas payload differs");
	CHECK(ftab_get_entry_ptr(ft, 0x6e6f6e65, &p, &ps) != 0, "missing tag was found");

	CHECK(ftab_add_entry(ft, 0x74657374, "hello", 5) == 0, "ftab_add_entry failed");
	void *out = NULL;
	size_t os = 0;
	CHECK(ftab_write(ft, &out, &os) == 0, "ftab_write failed");
	if (out) {
		const uint8_t *o = out;
		/* 48 header + 3*16 entries + 32 + 20 + 5 payload bytes */
		CHECK(os == 153, "ftab output size %zu, want 153", os);
		CHECK(os == 153 && memcmp(o + 0x24, "ftab", 4) == 0 && o[0x28] == 3, "ftab header: magic/num_entries");
		/* entry 2: tag 'test' (BE), offset 0x94 (LE), size 5 (LE) */
		CHECK(os == 153 && memcmp(o + 0x50, "test", 4) == 0 && o[0x54] == 0x94 && o[0x58] == 5, "ftab entry 'test'");
		CHECK(os == 153 && memcmp(o + 0x94, "hello", 5) == 0, "ftab appended payload");
		CHECK_CRC("ftab output", o, os, 153, FTAB_GOLDEN_CRC);
		free(out);
	}
	ftab_free(ft);
	free(img);
}

static void test_mbn(void)
{
	uint8_t *raw;
	struct fuzz_input in;
	if (load_framed("fuzz_mbn/testsuite/v1_image", &raw, &in) != 0) {
		return;
	}
	uint8_t *out = mbn_stitch(in.a, in.a_size, in.b, in.b_size);
	CHECK(out != NULL, "mbn_stitch (v1) returned NULL");
	if (out) {
		/* the signature blob replaces the tail of the v1 image; everything before it is untouched */
		size_t at = in.a_size - in.b_size;
		CHECK(memcmp(out, in.a, at) == 0, "mbn v1 head modified");
		CHECK(memcmp(out + at, in.b, in.b_size) == 0, "mbn v1 blob not stitched at the tail");
		free(out);
	}
	/* a zero-length blob is refused */
	CHECK(mbn_stitch(in.a, in.a_size, in.b, 0) == NULL, "mbn_stitch accepted an empty blob");
	free(raw);
}

static void test_fls(void)
{
	uint8_t *raw;
	struct fuzz_input in;

	if (load_framed("fuzz_fls/testsuite/update_sig_blob", &raw, &in) == 0) {
		size_t rs = 0;
		uint8_t *rawfls = fuzz_fls_build(in.a, in.a_size, &rs);
		/* the element records serialize to the 4-element, 180-byte container the golden outputs derive from */
		CHECK(rawfls != NULL && rs == 180, "fuzz_fls_build: size %zu, want 180", rs);
		fls_file *f = rawfls ? fls_parse(rawfls, rs) : NULL;
		free(rawfls);
		CHECK(f != NULL && f->num_elements == 4, "fls_parse: elements %u, want 4", f ? f->num_elements : 0);
		if (f) {
			CHECK(fls_update_sig_blob(f, in.b, in.b_size) == 0, "fls_update_sig_blob failed");
			CHECK(f->data && f->size == 184 && memmem(f->data, f->size, in.b, in.b_size) != NULL,
			      "fls update: blob not embedded (size %zu)", f->size);
			CHECK_CRC("fls update", f->data, f->size, 184, FLS_UPDATE_GOLDEN_CRC);
			fls_free(f);
		}
		free(raw);
	}

	if (load_framed("fuzz_fls/testsuite/insert_ticket", &raw, &in) == 0) {
		size_t rs = 0;
		uint8_t *rawfls = fuzz_fls_build(in.a, in.a_size, &rs);
		fls_file *f = rawfls ? fls_parse(rawfls, rs) : NULL;
		free(rawfls);
		if (f) {
			CHECK(fls_insert_ticket(f, in.b, in.b_size) == 0, "fls_insert_ticket failed");
			CHECK(f->data && f->size == 200 && memmem(f->data, f->size, in.b, in.b_size) != NULL,
			      "fls insert: ticket not embedded (size %zu)", f->size);
			CHECK_CRC("fls insert", f->data, f->size, 200, FLS_INSERT_GOLDEN_CRC);
			fls_free(f);
		} else {
			CHECK(0, "fls_parse of the insert fixture failed");
		}
		free(raw);
	}
}

static void test_img3(void)
{
	uint8_t *raw;
	struct fuzz_input in;
	if (load_framed("fuzz_img3/testsuite/component_blob_size_mismatch", &raw, &in) != 0) {
		return;
	}
	void *out = NULL;
	size_t os = 0;
	/* the blob's first element does not describe the blob size, so the stitch is refused */
	CHECK(img3_stitch_component("iBSS", in.a, in.a_size, in.b, in.b_size, &out, &os) == -1 && out == NULL,
	      "img3_stitch_component accepted a blob with a mismatched size");
	CHECK(img3_stitch_component("iBSS", in.a, in.a_size, NULL, 0, &out, &os) == -1, "img3 accepted a NULL blob");
	free(raw);

	/* the caller's shape: the buffer holds ECID+SHSH+CERT (236 bytes), blob_size is the ECID element's size (20) */
	static const char *const fixtures[] = {"fuzz_img3/testsuite/component_replace_signature",
					       "fuzz_img3/testsuite/component_insert_signature"};
	for (size_t i = 0; i < 2; i++) {
		if (load_framed(fixtures[i], &raw, &in) != 0) {
			continue;
		}
		uint32_t first_size = 0;
		memcpy(&first_size, in.b + 4, 4);
		CHECK(first_size == 20 && in.b_size == 236, "%s: blob is %zu bytes, first element %u", fixtures[i], in.b_size,
		      first_size);
		out = NULL;
		os = 0;
		int rc = img3_stitch_component("iBSS", in.a, in.a_size, in.b, first_size, &out, &os);
		CHECK(rc == 0 && out != NULL, "%s: img3_stitch_component failed (%d)", fixtures[i], rc);
		if (rc == 0 && out) {
			const uint8_t *o = out;
			uint32_t hdr_full = 0, hdr_data = 0, hdr_shsh = 0;
			/* TYPE+DATA+VERS+KBAG (136 bytes) keep their place, then ECID+SHSH+CERT from the blob */
			CHECK(os == 20 + 136 + 236, "%s: stitched size %zu, want 392", fixtures[i], os);
			if (os == 392) {
				memcpy(&hdr_full, o + 4, 4);
				memcpy(&hdr_data, o + 8, 4);
				memcpy(&hdr_shsh, o + 12, 4);
				CHECK(hdr_full == 392 && hdr_data == 372, "%s: header sizes %u/%u", fixtures[i], hdr_full, hdr_data);
				CHECK(hdr_shsh == 156, "%s: shsh_offset %u, want 156", fixtures[i], hdr_shsh);
				CHECK(memcmp(o + 20, in.a + 20, 136) == 0, "%s: leading elements changed", fixtures[i]);
				CHECK(memcmp(o + 156, in.b, 236) == 0, "%s: signature elements are not the blob's", fixtures[i]);
				CHECK(memcmp(o + 156, "DICE", 4) == 0 && memcmp(o + 176, "HSHS", 4) == 0 && memcmp(o + 316, "TREC", 4) == 0,
				      "%s: element order is not ECID/SHSH/CERT", fixtures[i]);
			}
			free(out);
		}
		free(raw);
	}
}

static void test_img4(void)
{
	uint8_t *raw;
	struct fuzz_input in;
	if (load_framed("fuzz_img4/testsuite/ibss_ticket", &raw, &in) != 0) {
		return;
	}
	plist_t tss = NULL;
	plist_from_memory((const char *)in.b, (uint32_t)in.b_size, &tss, NULL);
	plist_t params = plist_new_dict();
	plist_dict_set_item(params, "RequiresNonceSlot", plist_new_bool(0));
	void *out = NULL;
	size_t os = 0;
	CHECK(tss != NULL, "TSS fixture did not parse");
	CHECK(img4_stitch_component("iBSS", in.a, in.a_size, params, tss, &out, &os) == 0, "img4_stitch_component failed");
	if (out) {
		const uint8_t *o = out;
		/* SEQUENCE(162) { "IMG4", SEQUENCE(84) IM4P{"IM4P","ibss","desc",OCTET STRING(64)}, [0](68) ticket } */
		static const uint8_t head[] = {0x30, 0x81, 0xa2, 0x16, 0x04, 'I', 'M', 'G', '4',
		                               0x30, 0x54, 0x16, 0x04, 'I', 'M', '4', 'P',
		                               0x16, 0x04, 'i', 'b', 's', 's', 0x16, 0x04, 'd', 'e', 's', 'c', 0x04, 0x40};
		CHECK(os == 165, "img4 output size %zu, want 165", os);
		CHECK(os == 165 && memcmp(o, head, sizeof(head)) == 0, "img4 DER header differs");
		CHECK(os == 165 && memcmp(o + sizeof(head), in.a + in.a_size - 64, 64) == 0, "img4 payload differs");
		CHECK(os == 165 && o[95] == 0xa0 && o[96] == 0x44 && o[97] == 0x30 && o[98] == 0x82, "img4 ticket wrapper differs");
		CHECK_CRC("img4 output", o, os, 165, IMG4_GOLDEN_CRC);
		free(out);
	}
	plist_free(params);
	plist_free(tss);
	free(raw);
}

static const void *memmem_find(const uint8_t *h, size_t hn, const char *needle)
{
	return memmem(h, hn, needle, strlen(needle));
}

static void test_img4_local_manifest(void)
{
	uint8_t *raw;
	struct fuzz_input in;
	if (load_framed("fuzz_img4/testsuite/local_manifest_identity", &raw, &in) != 0) {
		return;
	}
	plist_t request = NULL, identity = NULL, manifest = NULL;
	plist_from_memory((const char *)in.a, (uint32_t)in.a_size, &request, NULL);
	plist_from_memory((const char *)in.b, (uint32_t)in.b_size, &identity, NULL);
	CHECK(request && identity, "local manifest fixtures did not parse");
	CHECK(img4_create_local_manifest(NULL, identity, &manifest) == -1, "local manifest accepted a NULL request");
	CHECK(request && img4_create_local_manifest(request, identity, &manifest) == 0 && manifest, "img4_create_local_manifest failed");
	if (manifest) {
		uint64_t n = 0;
		const uint8_t *m = (const uint8_t *)plist_get_data_ptr(manifest, &n);
		/* DER SEQUENCE { IA5String "IM4M", INTEGER 0, SET { MANB, MANP, one entry per component } } */
		CHECK(m && n > 4 && m[0] == 0x30, "local manifest is not a DER SEQUENCE");
		CHECK(m && n > 4 && ((m[1] == 0x82 && (size_t)((m[2] << 8) | m[3]) + 4 == n) || (m[1] == 0x81 && (size_t)m[2] + 3 == n)),
		      "local manifest outer length does not match its size %zu", (size_t)n);
		CHECK(m && memmem_find(m, n, "IM4M") && memmem_find(m, n, "MANB") && memmem_find(m, n, "MANP"), "local manifest lacks IM4M/MANB/MANP");
		/* iBSS is renamed by the identity's Img4PayloadType, SEP by the built-in tag table, 'Unlisted' keeps the identity's tag */
		CHECK(m && memmem_find(m, n, "ibss") && memmem_find(m, n, "sepi") && memmem_find(m, n, "rsep") && memmem_find(m, n, "unls"),
		      "local manifest component tags differ");
		CHECK(m && !memmem_find(m, n, "iBSS") && !memmem_find(m, n, "Unlisted"), "local manifest kept an unmapped component name");
		CHECK_CRC("img4 local manifest", m, n, IMG4_MANIFEST_GOLDEN_SIZE, IMG4_MANIFEST_GOLDEN_CRC);
	}
	plist_free(manifest);
	plist_free(request);
	plist_free(identity);
	free(raw);
}

static void test_ace3(void)
{
	uint8_t *raw;
	struct fuzz_input in;
	if (load_framed("fuzz_ace3/testsuite/board_0x10", &raw, &in) != 0) {
		return;
	}
	plist_t tss = NULL;
	plist_from_memory((const char *)in.b, (uint32_t)in.b_size, &tss, NULL);
	void *out = NULL;
	size_t os = 0;
	CHECK(tss != NULL, "ACE3 TSS fixture did not parse");
	CHECK(ace3_create_binary(in.a, in.a_size, 0x10, 0, tss, &out, &os) == 0, "ace3_create_binary failed");
	if (out) {
		const uint8_t *o = out;
		CHECK(os == 160, "ace3 output size %zu, want 160", os);
		CHECK(os == 160 && o[0] == 0x03 && o[1] == 0x00 && o[2] == 0xe0 && o[3] == 0xac, "ace3 magic 0xACE00003");
		CHECK(os == 160 && memmem(o, os, "1111111111111111", 16) && memmem(o, os, "222222222222", 12),
		      "ace3 payloads DA01/DA02 missing");
		CHECK(memmem(o, os, "IM4M", 4) != NULL, "ace3 ticket missing");
		CHECK_CRC("ace3 output", o, os, 160, ACE3_GOLDEN_CRC);
		free(out);
	}
	/* a board id with no matching payload is refused */
	void *none = NULL;
	size_t ns = 0;
	CHECK(ace3_create_binary(in.a, in.a_size, 0x7f, 0, tss, &none, &ns) != 0, "ace3 built a binary for an unknown board");
	plist_free(tss);
	free(raw);
}

static void test_ipsw(void)
{
	char path[1024];
	snprintf(path, sizeof(path), "%s/mayhem/fuzz_ipsw/testsuite/iphone_ipsw.zip", root);
	ipsw_archive_t ar = ipsw_open(path);
	CHECK(ar != NULL, "ipsw_open failed for %s", path);
	if (!ar) {
		return;
	}
	CHECK(ipsw_file_exists(ar, "BuildManifest.plist") == 1, "BuildManifest.plist not found in the archive");
	CHECK(ipsw_file_exists(ar, "nonexistent.bin") == 0, "a missing member was reported present");

	plist_t manifest = NULL;
	int tss = 0;
	CHECK(ipsw_extract_build_manifest(ar, &manifest, &tss) == 0 && manifest != NULL, "build manifest extraction failed");
	if (manifest) {
		char *ver = NULL;
		plist_t v = plist_dict_get_item(manifest, "ProductVersion");
		if (v) {
			plist_get_string_val(v, &ver);
		}
		CHECK(ver && strcmp(ver, "17.4") == 0, "ProductVersion %s, want 17.4", ver ? ver : "(null)");
		free(ver);
		plist_free(manifest);
	}

	plist_t restore = NULL;
	CHECK(ipsw_extract_restore_plist(ar, &restore) == 0 && restore != NULL, "Restore.plist extraction failed");
	if (restore) {
		char *pt = NULL;
		plist_t v = plist_dict_get_item(restore, "ProductType");
		if (v) {
			plist_get_string_val(v, &pt);
		}
		CHECK(pt && strcmp(pt, "iPhone15,2") == 0, "ProductType %s, want iPhone15,2", pt ? pt : "(null)");
		free(pt);
		plist_free(restore);
	}
	ipsw_close(ar);
}

int main(int argc, char **argv)
{
	root = argc > 1 ? argv[1] : ".";
	fuzz_quiet_logging();
	test_ftab();
	test_mbn();
	test_fls();
	test_img3();
	test_img4();
	test_img4_local_manifest();
	test_ace3();
	test_ipsw();
	printf("SELFTEST passed=%d failed=%d\n", passed, failed);
	return failed ? 1 : 0;
}
