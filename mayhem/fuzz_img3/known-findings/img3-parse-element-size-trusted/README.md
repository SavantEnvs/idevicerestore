# img3_parse_element: element full_size is trusted

`img3_parse_element` (src/img3.c:212-220) takes `element_header->full_size` from the input and uses it for `malloc`, `memcpy` and a 4-byte read of the copy, without checking it against the bytes that remain in the file (`img3_parse_file` never passes the remaining size) or against the 12-byte element header. One cause, three effects.

## Run 4 (300 s), 34 defects (of the target's 39), 3 lines

| line | what | defects | reproducer |
|---|---|---|---|
| `img3.c:212` | `malloc(full_size)` with a huge size: libFuzzer's malloc limit reports it here (8 "excessive allocation size"); the `full_size` read on the same line is also out of bounds when the element header is cut off by the end of the file (3 reads) or misaligned when the previous element's `full_size` is odd (2 UBSan reports) | 13 | `reproducer-truncated-header` (element header cut off after 4 bytes), `reproducer-excessive-size`, `reproducer-misaligned` |
| `img3.c:218` | `memcpy(element->data, data, full_size)` reads past the file | 13 out-of-bounds reads | `reproducer` (`full_size` 256, 12 bytes present) |
| `img3.c:220` | `element->header->signature` read from a copy shorter than 4 bytes (`full_size` 0-3) | 8 out-of-bounds reads | `reproducer-short-element` (`full_size` 2) |

The `reproducer-excessive-size` file (`full_size` 0x80000000) only reports at `:212` under libFuzzer (`-malloc_limit_mb`, default 2048). The standalone binary has no malloc limit, so there the same input proceeds to the `:218` overflow. `reproducer-misaligned` (a 13-byte element, so the next one starts at an odd offset) reports a misaligned `img3_element_header` access at `:67` or `:212` depending on the compiler.

Reproduce with `/mayhem/fuzz_img3-standalone <file>`; the files are framed `[selector][split LE16][A = component][B = blob]`.

An upstream fix is to pass the remaining size into `img3_parse_element` and reject `full_size < sizeof(img3_element_header)` or `> remaining`.
