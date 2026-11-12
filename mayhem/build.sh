#!/usr/bin/env bash
#
# mayhem/build.sh — builds the idevicerestore parsers (sanitized, for fuzzing) and the KAT selftest
# (normal flags, for test.sh). Runs inside the commit image as `mayhem` in /mayhem.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Upstream's .gitignore swallows the generated autotools files, so they are (re)created here.
NOCONFIGURE=1 ./autogen.sh

# Static deps built once into the image (Dockerfile); apt's copies are too old for upstream's configure.
DEPS=/opt/toolchains/deps
PKGP="$DEPS/libtatsu-1.0.5/lib/pkgconfig:$DEPS/libirecovery-1.3.1/lib/pkgconfig:$DEPS/libimobiledevice-1.4.0/lib/pkgconfig"
export PKG_CONFIG_PATH="$PKGP${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

# Objects of upstream's idevicerestore binary; its main() is renamed at compile time so they link as a library.
OBJS="ace3 asr common dfu download fdr fls ftab idevicerestore img3 img4 ipsw limera1n locking log mbn normal recovery restore"
objs_in() { local d=$1 o; for o in $OBJS; do printf '%s ' "$d/src/idevicerestore-$o.o"; done; }

# build_objs <dir> <cflags>: out-of-tree configure + compile of the objects above.
build_objs() {
  local dir=$1 cflags=$2 o targets=""
  rm -rf "$dir"; mkdir -p "$dir"
  (cd "$dir" && "$SRC/configure" CC="$CC" CFLAGS="$cflags" LDFLAGS="" >configure.log 2>&1) \
    || { tail -50 "$dir/configure.log" >&2; exit 1; }
  for o in $OBJS; do targets="$targets idevicerestore-$o.o"; done
  make -C "$dir/src" -j"$MAYHEM_JOBS" CFLAGS="$cflags -Dmain=idevicerestore_cli_main" $targets
}

# Link line shared by every binary: the static deps from /opt (whose pkg-config files list their private
# libs), then the system's shared libs.
LIBS="$(pkg-config --static --libs libimobiledevice-1.0 libirecovery-1.0 libtatsu-1.0) $(pkg-config --libs libzip libcurl libusbmuxd-2.0 openssl zlib libplist-2.0) -lbz2 -llzma -lunistring -lm"
PKG_INCS="$(pkg-config --cflags libimobiledevice-1.0 libirecovery-1.0 libtatsu-1.0 libzip libcurl libusbmuxd-2.0 openssl zlib libplist-2.0) -I$SRC/src -I$SRC/mayhem"

# 1) The project with sanitizers + coverage instrumentation, so the fuzzed parsers are instrumented.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
build_objs "$SRC/mayhem/build-fuzz" "$FUZZ_CFLAGS"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$SRC/mayhem/build-fuzz/lsan_off.o"

# 2) Each harness twice: libFuzzer, and the standalone run-once reproducer.
for t in fuzz_ftab fuzz_fls fuzz_mbn fuzz_img3 fuzz_img4 fuzz_ace3 fuzz_ipsw; do
  $CC $FUZZ_CFLAGS $PKG_INCS -I"$SRC/mayhem/build-fuzz" -DHAVE_CONFIG_H -c "$SRC/mayhem/$t.c" -o "$SRC/mayhem/build-fuzz/$t.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/build-fuzz/$t.o" \
      $(objs_in "$SRC/mayhem/build-fuzz") "$SRC/mayhem/build-fuzz/lsan_off.o" $LIBS -o "/mayhem/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "$SRC/mayhem/build-fuzz/$t.o" \
      $(objs_in "$SRC/mayhem/build-fuzz") "$SRC/mayhem/build-fuzz/lsan_off.o" $LIBS -o "/mayhem/$t-standalone"
done

# 3) The test suite: the same sources with the project's normal flags, no sanitizers.
build_objs "$SRC/mayhem/build-test" "-O2 -g $COVERAGE_FLAGS"
$CC -O2 -g $COVERAGE_FLAGS $PKG_INCS -I"$SRC/mayhem/build-test" -DHAVE_CONFIG_H "$SRC/mayhem/selftest.c" \
    $(objs_in "$SRC/mayhem/build-test") $LIBS -o /mayhem/idevicerestore_selftest
