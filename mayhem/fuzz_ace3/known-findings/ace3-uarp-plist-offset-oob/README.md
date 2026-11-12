# ace3_create_binary: unchecked UARP plist_offset

`ace3_create_binary` (src/ace3.c:127-130) computes `plist_size = uarp_size - plist_offset` from an attacker-controlled header field with no check that `plist_offset <= uarp_size`, then hands the out-of-range pointer to `nskeyedarchive_new_from_data`: SEGV in libimobiledevice-glue. Reproduce with `/mayhem/fuzz_ace3-standalone reproducer`.
