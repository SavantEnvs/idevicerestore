# ace3_create_binary: unbounded recursion in libimobiledevice-glue on cyclic NSKeyedArchive UIDs

The UARP file's trailing plist is decoded by `nskeyedarchive_new_from_data` (libimobiledevice-glue). When the archive's `$objects` graph refers back to itself (a `NS.objects` entry whose UID points at an ancestor), `nskeyedarchive_get_object_by_uid` -> `nskeyedarchive_get_objects` recurses with no depth or visited-set check, until the stack is exhausted. ASan reports `stack-overflow`; Mayhem's backtrace for the same input is `strcmp` <- `plist_dict_get_item` <- `nskeyedarchive_get_objects` <- `nskeyedarchive_get_object_by_uid` repeated hundreds of times, with no idevicerestore frame, which is why Mayhem files it as `Uncontrolled Resource Consumption` with no app frame.

It is input-driven: the 1455-byte `reproducer` (framed `[selector][split][UARP][TSS]`) is a mutation of the `board_0x10` seed, and four distinct Mayhem corpus files give the same overflow. The harness allocates nothing proportional to the input. The fix belongs in libimobiledevice-glue (cap the recursion depth).

Reproduce with `/mayhem/fuzz_ace3-standalone reproducer`.

## Run 4 (300 s): 20 defects

The recursion above is the one defect with no idevicerestore frame. The other 19 all have their first app frame in `ace3_create_binary` (src/ace3.c) and come from header, table and plist fields that are never checked against the buffer:

- `:127`, `:128` (1 each): `uarp_hdr->header_size` / `plist_offset` read from a UARP shorter than its header (out-of-bounds reads); `:130` (1): `plist_offset` past the end, see `ace3-uarp-plist-offset-oob`.
- `:134` (4): NULL dereference inside libimobiledevice-glue's `nskeyedarchive_to_plist` for a decoded archive that is not the expected shape.
- `:224` (2, one out-of-bounds read and one misaligned access) and `:237` (1): TOC entry fields (`this_size`, `fourcc`) read without checking the entry lies inside the buffer.
- `:246` (1): `malloc(0x40 + content_size)` with an unchecked, huge `content_size` (excessive allocation size).
- `:263`, `:265`, `:269` (2, 3, 2) and `:267` (1 NULL dereference): `memcpy` of the data1, data2, IM4M and dl regions with offsets/sizes from the TOC, never checked against the UARP size (`:267` is a NULL dereference in the IM4M copy).
