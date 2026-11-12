# ftab_parse: unchecked entry offset/size

`ftab_parse` (src/ftab.c:76) `memcpy`s `entries[i].size` bytes from `data + entries[i].offset` without checking either against the input size: heap-buffer-overflow read. Reproduce with `/mayhem/fuzz_ftab-standalone reproducer`.

## Run 4 (300 s): 10 defects, one cause

All ten share one cause, an entry table that is never validated against the file size, in `ftab_parse`: excessive allocation sizes at src/ftab.c:62 and :75 (1 each), out-of-bounds entry offset/size accesses at :63 (2) and :76 (6, this README's reproducer).
