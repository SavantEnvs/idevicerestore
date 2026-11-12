# img4_stitch_component: asn1_get_element reads past the component

`asn1_get_element` (src/img4.c:220) reads the tag/length bytes without a bounds check against the remaining buffer: heap-buffer-overflow, reached via `asn1_find_element` from `img4_stitch_component` (src/img4.c:430). Reproduce with `/mayhem/fuzz_img4-standalone reproducer`.

## Run 4 (300 s): 5 defects

- src/img4.c:220 (`asn1_get_element`, 2: one out-of-bounds read, one use-after-free): element tag/length bytes trusted against the remaining buffer.
- src/img4.c:712 (`img4_stitch_component`, 1): NULL dereference on a missing element.
- src/img4.c:178 (`asn1_write_element`, 1): NULL dereference in the `memcpy` of an element's data, found since the manifest mode (`img4_create_local_manifest`) was added.
- src/img4.c:780 (`_manifest_write_component`, 1): `*(uint32_t*)tag` reads 4 bytes of the component tag even when it is shorter; also new with manifest mode.
