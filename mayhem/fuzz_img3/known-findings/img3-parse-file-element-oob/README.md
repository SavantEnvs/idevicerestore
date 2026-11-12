# img3_parse_file: header and element-header reads past the end of the buffer

`img3_parse_file` (src/img3.c) trusts that the buffer holds a whole header and whole element headers. `img3_stitch_component` hands it `component_size` bytes with no minimum, so each of these reads runs off the heap buffer: heap-buffer-overflow.

The `img3_parse_element` defects (the bulk of the run) are a separate cause, see `../img3-parse-element-size-trusted/`; the `img3_stitch_component` short-blob defect is `../img3-stitch-short-blob/`.

## Run 4 (300 s), 4 defects, 3 lines

| line | what | defects | reproducer |
|---|---|---|---|
| `img3.c:40` | `header->signature` read from a component shorter than 4 bytes | 1 out-of-bounds read | `reproducer` (1-byte component) |
| `img3.c:61` | `memcpy` of the 20-byte `img3_header` from a component of 4-19 bytes | 1 out-of-bounds read | `reproducer-header-memcpy` (12-byte component) |
| `img3.c:67` | `current->signature` read when fewer than 4 bytes follow the last element (also UBSan: misaligned `img3_element_header` access when a `full_size` is not a multiple of 4) | 1 out-of-bounds read, 1 misaligned access | `reproducer-trailing-bytes` (header + 2 bytes) |

Reproduce with `/mayhem/fuzz_img3-standalone <file>`. The files are framed `[selector][split LE16][A = component][B = blob]`.
