# mbn_stitch: stitch offset derived from the ELF is never checked against the image size

`mbn_stitch` (src/mbn.c:278) computes `stitch_offset` from the image's ELF program headers and then does
`memcpy(buf + stitch_offset, blob, blob_size)` into a `data_size`-byte buffer without checking
`stitch_offset + blob_size <= data_size`: heap-buffer-overflow write. Reproduce with
`/mayhem/fuzz_mbn-standalone reproducer`.

## Run 4 (300 s): 9 defects

- src/mbn.c:226, :233, :249 (1 each, `mbn_stitch`): ELF program-header offset/size trusted (out-of-bounds reads).
- src/mbn.c:278 (2: one heap-buffer overflow write, one use-after-free): the final `memcpy` into a buffer sized from unvalidated header fields.
- one more `mbn_stitch` out-of-bounds read whose frame has no line number.
- src/mbn.c:375 and :384 (1 each, `mbn_mav25_stitch`): `e_phoff` read from data shorter than the ELF header (:375) and `phdr[e_phnum-1]` read from a table at an unchecked offset (:384); found since the mav25 seeds.
- src/mbn.c:313 (1, `mbn_v7_log_header` called from `mbn_mav25_stitch` at :422; Mayhem files it as use-after-free, CWE-416): `mbn_mav25_stitch` checks `sect_off + sect_size > data_size` (:411) with `off_t` plus `size_t`. A `p_offset` of `(uint64_t)-16` with `p_filesz` 0x100 sums to 0xF0 modulo 2^64, so the check passes, and `header = data + sect_off` (:421) points 16 bytes before the image. The first read of `header->version` at :313 is then outside the buffer; in the Mayhem run that memory had been freed (use-after-free), under the standalone binary it is a heap-buffer-overflow read. `reproducer-mav25-wrap` is a hand-built ELF64 with that one program header (no Mayhem input of this defect was saved); reproduce with `/mayhem/fuzz_mbn-standalone reproducer-mav25-wrap`. A library fix is to compare `sect_off` and `sect_size` separately against `data_size`.
