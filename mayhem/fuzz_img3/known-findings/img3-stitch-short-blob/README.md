# img3_stitch_component: blob shorter than 8 bytes

`img3_stitch_component` (src/img3.c:424) reads `((img3_element_header*)blob)->full_size` (bytes 4-7 of the blob) once `blob_size` is non-zero, without checking `blob_size >= 8`: heap-buffer-overflow read. 1 defect in run 4 (300 s).

`reproducer` is a valid, empty IMG3 (header only) as component and a 4-byte blob. Reproduce with `/mayhem/fuzz_img3-standalone reproducer`.

## Not reachable from idevicerestore.c; a library hardening gap

The only caller (src/idevicerestore.c:2892) passes `blob_size` = 64, and a blob buffer from `tss_response_get_blob_by_entry`, which holds the ECID/SHSH/CERT element sequence (at least the 64 bytes passed). A 1-7 byte blob is a case the real caller does not produce, so this is a missing argument check in the library, not a bug reachable through the idevicerestore binary. `fuzz_img3.c` passes B unchanged when it is 1-7 bytes (the blob-size logic only substitutes B's first-element `full_size` for sizes it can read), so the fuzzer can send it.

No guard was added: the library's contract for `blob_size` is not documented, so there is no precondition to cite for rejecting a short blob in the harness, and the finding stays visible. The upstream fix is `if (blob_size < sizeof(img3_element_header)) return -1;`.
