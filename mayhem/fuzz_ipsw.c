// Fuzzes IPSW firmware archive handling through the library's path-based API: the input is written to a
// private scratch file (zip_open needs a path), then ipsw_print_info, ipsw_open, BuildManifest/Restore.plist
// extraction, size lookup and directory listing run over it.
#include <fcntl.h>
#include <plist/plist.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fuzz_common.h"
#include "ipsw.h"

static int list_cb(void *ctx, ipsw_archive_t ipsw, const char *name, struct stat *st)
{
	(void)ctx;
	(void)ipsw;
	(void)name;
	(void)st;
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	fuzz_quiet_logging();
	/* ipsw_print_info reports with printf; send it to a fixed-size in-memory sink (writes past the end just fail). */
	static char sink[1 << 16];
	stdout = fmemopen(sink, sizeof(sink), "w");
	return stdout ? 0 : 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *tmpdir = getenv("TMPDIR");
	char path[4096];
	snprintf(path, sizeof(path), "%s/ipsw-fuzz-XXXXXX", (tmpdir && *tmpdir) ? tmpdir : "/tmp");
	int fd = mkstemp(path);
	if (fd < 0) {
		abort();
	}
	size_t done = 0;
	while (done < size) {
		ssize_t n = write(fd, data + done, size - done);
		if (n <= 0) {
			close(fd);
			unlink(path);
			abort();
		}
		done += (size_t)n;
	}
	close(fd);

	ipsw_print_info(path);

	int rc = -1;
	ipsw_archive_t ipsw = ipsw_open(path);
	if (ipsw) {
		rc = 0;
		plist_t manifest = NULL;
		plist_t restore = NULL;
		int tss_enabled = 0;
		uint64_t fsize = 0;
		ipsw_extract_build_manifest(ipsw, &manifest, &tss_enabled);
		ipsw_extract_restore_plist(ipsw, &restore);
		ipsw_get_file_size(ipsw, "BuildManifest.plist", &fsize);
		ipsw_file_exists(ipsw, "Restore.plist");
		ipsw_list_contents(ipsw, list_cb, NULL);
		plist_free(manifest);
		plist_free(restore);
		ipsw_close(ipsw);
	}

	unlink(path);
	return rc;
}
