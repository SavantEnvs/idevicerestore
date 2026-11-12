# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form, PREFERRED) — builds ON TOP of the org C/C++ base
# image (ghcr.io/savantenvs/base). The base already provides debian + clang/llvm +
# libFuzzer/afl++ + the identities + the build-contract ENV, so this only adds the
# per-commit build (built on top of the prebuilt base, rather than building the toolchain in-image).
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .

# The org base, pinned to a fixed DATE-tagged base (YYYYMMDD; shared by all integrations
# minted against it). Use the current dated tag; pin by digest in production: ...base@sha256:<digest>.
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); do NOT bake it as an ENV — an
# empty value breaks clang ("must be a non-negative decimal integer") both here and for
# any in-image rebuild. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# To change it for a build (e.g. ASan-only, or add MSan): --build-arg SANITIZER_FLAGS="...".
# Declare it WITHOUT a default (no '='): an undefaulted ARG lets the base ENV flow through to
# build.sh when not passed, and an explicit --build-arg overrides it. (An empty default — `=` —
# would instead shadow the base ENV and silently wipe the sanitizers.)
ARG SANITIZER_FLAGS
# Coverage (optional, off by default): instrument the TEST build to measure how much of the project
# the suite exercises — --build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping".
# Empty by default (no effect on the normal oracle build); build.sh appends it to the test build only.
ARG COVERAGE_FLAGS=
# Build parallelism (optional). build.sh falls back to nproc when unset: --build-arg MAYHEM_JOBS=8
ARG MAYHEM_JOBS=

# idevicerestore's configure needs libtatsu >= 1.0.5, libirecovery >= 1.3.1 and libimobiledevice >= 1.4.0, newer
# than the apt copies. Each is built once from its pinned release tarball into a static, -gdwarf-3 prefix under
# /opt/toolchains/deps/<name>-<version>/ (root-owned, world-readable); mayhem/build.sh points pkg-config at them.
# The rest comes from apt: libusb/libudev (libirecovery), libzip, curl, openssl, plus the bz2/lzma/unistring
# archives that the static link line needs.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        bzip2 libbz2-dev libcurl4-openssl-dev libimobiledevice-glue-dev liblzma-dev libplist-dev libssl-dev \
        libudev-dev libunistring-dev libusb-1.0-0-dev libusbmuxd-dev libzip-dev \
 && rm -rf /var/lib/apt/lists/*

ARG LIBTATSU_VER=1.0.5
ARG LIBTATSU_SHA256=536fa228b14f156258e801a7f4d25a3a9dd91bb936bf6344e23171403c57e440
ARG LIBIRECOVERY_VER=1.3.1
ARG LIBIRECOVERY_SHA256=28a3a521782063c8eb2ee5f4c0f38a517e023853edb55856052cdd7ac400381b
ARG LIBIMOBILEDEVICE_VER=1.4.0
ARG LIBIMOBILEDEVICE_SHA256=23cc0077e221c7d991bd0eb02150a0d49199bcca1ddf059edccee9ffd914939d
RUN set -eux; \
    build_dep() { \
      name=$1; ver=$2; sha=$3; shift 3; \
      d=/opt/toolchains/deps/$name-$ver; \
      mkdir -p "$d/src" /tmp/dep-build; \
      curl -fsSL -o /tmp/dep.tar.bz2 "https://github.com/libimobiledevice/$name/releases/download/$ver/$name-$ver.tar.bz2"; \
      echo "$sha  /tmp/dep.tar.bz2" | sha256sum -c -; \
      tar -xjf /tmp/dep.tar.bz2 --strip-components=1 -C "$d/src"; \
      (cd /tmp/dep-build && "$d/src/configure" --prefix="$d" --disable-shared --enable-static "$@" \
          CFLAGS="-O2 -g -gdwarf-3 -fPIC" && make -j"$(nproc)" install); \
      rm -rf /tmp/dep-build /tmp/dep.tar.bz2; chmod -R a+rX "$d"; \
    }; \
    export PKG_CONFIG_PATH=; \
    build_dep libtatsu "$LIBTATSU_VER" "$LIBTATSU_SHA256"; \
    export PKG_CONFIG_PATH=/opt/toolchains/deps/libtatsu-$LIBTATSU_VER/lib/pkgconfig; \
    build_dep libirecovery "$LIBIRECOVERY_VER" "$LIBIRECOVERY_SHA256"; \
    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/opt/toolchains/deps/libirecovery-$LIBIRECOVERY_VER/lib/pkgconfig; \
    build_dep libimobiledevice "$LIBIMOBILEDEVICE_VER" "$LIBIMOBILEDEVICE_SHA256" --without-cython
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git
# history) is copied to /mayhem as `mayhem`; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Anything a Dockerfile step materializes into the tree (downloaded fixtures, generated headers,
# vendored deps) MUST be committed or (re)created by build.sh: rlenv's patch grader runs
# `git clean -ffdX` before every graded build, so a gitignored, untracked file is gone by then and
# every honest patch scores zero (SPEC §6.2 item 16; verify-repo.sh checks it).
#
# OPTIONAL compile-cache pre-fill (SPEC §6.2 item 18). Bases minted with /opt/mayhem/ccache/prefill
# run the build under rlenv's pinned ccache, so the patch grader's first (otherwise cold) rebuild is
# warm — this is what keeps large C/C++ targets inside the build time limit. Older bases fall back to
# the plain build; a missing or stale pre-fill only costs a cold cache. Never enable ccache in
# build.sh or via ENV/PATH, and keep the compiler resolving by name (CC=clang) or nothing is cached.
RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

# Run the project's functional tests at build time IF the repo ships them (mayhem/test.sh is
# optional — omit it only when the repo has no tests meaningful for RL). A failing suite fails the
# image build, so the commit image is guaranteed to build AND pass its own tests.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
