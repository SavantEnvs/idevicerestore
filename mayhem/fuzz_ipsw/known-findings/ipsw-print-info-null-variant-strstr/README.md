# ipsw_print_info: strstr(NULL) when a build identity has no Variant

`ipsw_print_info` (src/ipsw.c:194) calls `strstr(variant_str, ...)` where `variant_str` is NULL for a build identity whose `Info` dict has no `Variant`: UBSan nonnull-attribute (and a NULL dereference without UBSan). Reproduce with `/mayhem/fuzz_ipsw-standalone reproducer`.

## Run 4 (300 s): 10 defects

- 7 asserts inside libplist (`plist_get_string_val` and friends, first frame `__assert_fail_base`): src/ipsw.c:139, :156 and :184 call them on a node that is not a string; one cause, no type check.
- src/ipsw.c:194 (1, this README's reproducer) and :202 (1): NULL dereference in `ipsw_print_info`.
- src/ipsw.c:1069 (1): out-of-bounds read in `ipsw_list_contents`.
