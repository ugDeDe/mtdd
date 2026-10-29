#!/usr/bin/env bash
# Reproducible fully-static x86_64-musl Release build of mtdd.
#
# The build uses $MTDD_STATIC_ROOT (default .local-build/static) and
# copies the final binary to $MTDD_STATIC_OUTPUT (default build-static/mtdd).
# It never uses host glibc libraries. It pins and
# verifies every downloaded archive before extraction, builds the three native
# dependencies (OpenSSL, libevent, curl) against the musl toolchain sysroot, and
# fails unless the produced executable has no PT_INTERP and no DT_NEEDED entry.
# OpenSSL is always built with thread support and the final binary is gated on
# real pthread lock calls (see tools/verify-static-locks.sh); a no-threads
# libcrypto crashes concurrent handshakes.
#
# Usage:
#   tools/build-static.sh                 # cached, incremental, full verification
#   tools/build-static.sh --clean         # remove the private build tree first
#   tools/build-static.sh --skip-verify   # build only (not for release evidence)
#   tools/build-static.sh --jobs 4
#   tools/build-static.sh --jobs4       # same, compact form
#
# Requirements on the host: bash, coreutils, curl, tar, xz, sha256sum,
# cmake >= 3.20, ninja, pkg-config, python3, file, readelf (binutils).
set -Eeuo pipefail
# Any unhandled failure prints the exact script line and command to the step
# log, so CI dumps identify the failing stage without extra debugging rounds.
trap 'status=$?; printf "\n==> FAILED: build-static.sh line %s, command: %s (exit %s)\n" \
    "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ROOT=${MTDD_STATIC_ROOT:-$REPO_ROOT/.local-build/static}
CACHE="$ROOT/cache"
SRC="$ROOT/src"
PREFIX="$ROOT/prefix"
BUILD="$ROOT/build"
OUT="$ROOT/out"
COPY=${MTDD_STATIC_OUTPUT:-$REPO_ROOT/build-static/mtdd}
LOGS="$ROOT/logs"
TOOLCHAIN_ROOT="$ROOT/toolchain"
JOBS=${MTDD_STATIC_JOBS:-8}
CLEAN=0
VERIFY=1

while (($#)); do
    case "$1" in
        --clean) CLEAN=1 ;;
        --skip-verify) VERIFY=0 ;;
        --jobs) JOBS=$2; shift ;;
        --jobs=*) JOBS=${1#--jobs=} ;;
        --jobs[0-9]*) JOBS=${1#--jobs} ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'BUILD FAILED: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing host tool: $1"; }

for tool in curl tar xz sha256sum cmake ninja pkg-config python3 file readelf; do need "$tool"; done
[[ -r /usr/include/nlohmann/json.hpp ]] || die "nlohmann/json.hpp header is required on the host"
grep -q 'version 3.12.0' /usr/include/nlohmann/json.hpp || die "expected nlohmann_json 3.12.0 header"
# A mixed host directory (pinned json.hpp + distro json_fwd.hpp, e.g. 3.11.3)
# poisons the staged prefix with mismatched ABI namespaces and fails the mtdd
# build with cryptic "incomplete type" errors, so gate the pair explicitly.
[[ -r /usr/include/nlohmann/json_fwd.hpp ]] || die "nlohmann/json_fwd.hpp header is required on the host"
grep -q 'version 3.12.0' /usr/include/nlohmann/json_fwd.hpp \
    || die "host nlohmann/json_fwd.hpp is not 3.12.0; install the pinned json.hpp AND json_fwd.hpp pair"

# ---------------------------------------------------------------------------
# Pinned inputs. Hashes are the upstream-published SHA-256 values.
# ---------------------------------------------------------------------------
TOOLCHAIN_NAME=x86-64--musl--stable-2025.08-1
TOOLCHAIN_TARBALL=$TOOLCHAIN_NAME.tar.xz
TOOLCHAIN_SHA256=09fca3aa89540f1b01b5f4210d488cbeb00f522044c53e9989b1dd8a38076912
TOOLCHAIN_URL=https://toolchains.bootlin.com/downloads/releases/toolchains/x86-64/tarballs/$TOOLCHAIN_TARBALL

OPENSSL_VERSION=3.5.9
OPENSSL_TARBALL=openssl-$OPENSSL_VERSION.tar.gz
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
OPENSSL_URL=https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/$OPENSSL_TARBALL

# OpenSSL disables thread support on its own when LDFLAGS contains "-static"
# (Configure: disable('static', 'pic', 'threads')). A no-threads libcrypto
# makes CRYPTO_THREAD_* no-ops, so concurrent handshakes corrupt shared
# provider/namemap state and abort in free(). Configure OpenSSL without the
# global -static LDFLAGS, request threads explicitly, and keep -pthread in its
# compile/link flags. The mtdd link itself is still fully static.
OPENSSL_TARGET=linux-x86_64
OPENSSL_CONFIG_OPTIONS=(threads no-shared no-module no-dso no-tests no-apps no-docs)
OPENSSL_CONFIGURE_CFLAGS="-O2 -fno-pie -pthread"
OPENSSL_CONFIGURE_LDFLAGS="-pthread"

LIBEVENT_VERSION=2.1.13-stable
LIBEVENT_TARBALL=libevent-$LIBEVENT_VERSION.tar.gz
LIBEVENT_SHA256=f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c
LIBEVENT_URL=https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION/$LIBEVENT_TARBALL

CURL_VERSION=8.23.0
CURL_TARBALL=curl-$CURL_VERSION.tar.xz
CURL_SHA256=8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5
CURL_URL=https://github.com/curl/curl/releases/download/curl-8_23_0/$CURL_TARBALL

# Optional allocator: MTDD_STATIC_MIMALLOC=1 links mimalloc's override object
# ahead of musl libc, replacing musl's mallocng (which unmaps freed groups
# eagerly and showed ~1k mmap/munmap per second under relay load).
MIMALLOC=${MTDD_STATIC_MIMALLOC:-0}
MIMALLOC_VERSION=2.1.7
MIMALLOC_TARBALL=mimalloc-$MIMALLOC_VERSION.tar.gz
MIMALLOC_SHA256=0eed39319f139afde8515010ff59baf24de9e47ea316a315398e8027d198202d
MIMALLOC_URL=https://github.com/microsoft/mimalloc/archive/refs/tags/v$MIMALLOC_VERSION.tar.gz

mkdir -p "$CACHE" "$SRC" "$PREFIX" "$BUILD" "$OUT" "$LOGS" "$TOOLCHAIN_ROOT"

if ((CLEAN)); then
    log "removing private build tree (downloads are kept)"
    rm -rf "$SRC" "$PREFIX" "$BUILD" "$OUT" "$TOOLCHAIN_ROOT"
    mkdir -p "$SRC" "$PREFIX" "$BUILD" "$OUT" "$TOOLCHAIN_ROOT"
fi

fetch() { # fetch <cache-file> <sha256> <url> [fallback-url...]
    local file=$CACHE/$1 sha=$2 name=$1
    shift 2
    if [[ ! -f $file ]]; then
        local url
        for url in "$@"; do
            [[ -n $url ]] || continue
            log "downloading $name from ${url%%/*}//…"
            if curl -fL --retry 6 --retry-delay 5 --connect-timeout 20 -o "$file.part" "$url"; then
                mv "$file.part" "$file"
                break
            fi
            rm -f "$file.part"
            log "source failed, trying the next mirror"
        done
    fi
    [[ -f $file ]] || die "download failed: $name"
    printf '%s  %s\n' "$sha" "$file" | sha256sum -c - >/dev/null \
        || die "checksum mismatch for $name"
    log "verified $name ($(stat -c %s "$file") bytes)"
}

MIRROR_URL=${MTDD_STATIC_MIRROR:-}
fetch "$TOOLCHAIN_TARBALL" "$TOOLCHAIN_SHA256" \
    "${MIRROR_URL:+$MIRROR_URL/$TOOLCHAIN_TARBALL}" "$TOOLCHAIN_URL"
fetch "$OPENSSL_TARBALL" "$OPENSSL_SHA256" "$OPENSSL_URL"
fetch "$LIBEVENT_TARBALL" "$LIBEVENT_SHA256" "$LIBEVENT_URL"
fetch "$CURL_TARBALL" "$CURL_SHA256" "$CURL_URL"
if ((MIMALLOC)); then fetch "$MIMALLOC_TARBALL" "$MIMALLOC_SHA256" "$MIMALLOC_URL"; fi

extract() { # extract <tarball> <target-dir> <sentinel-path>
    local tarball=$CACHE/$1 target=$2 sentinel=$3
    if [[ -e $sentinel ]]; then
        return
    fi
    log "extracting $1"
    mkdir -p "$target"
    tar -xf "$tarball" -C "$target"
}

extract "$TOOLCHAIN_TARBALL" "$TOOLCHAIN_ROOT" "$TOOLCHAIN_ROOT/$TOOLCHAIN_NAME/bin"
extract "$OPENSSL_TARBALL" "$SRC" "$SRC/openssl-$OPENSSL_VERSION/Configure"
extract "$LIBEVENT_TARBALL" "$SRC" "$SRC/libevent-$LIBEVENT_VERSION/configure"
extract "$CURL_TARBALL" "$SRC" "$SRC/curl-$CURL_VERSION/configure"
if ((MIMALLOC)); then
    extract "$MIMALLOC_TARBALL" "$SRC" "$SRC/mimalloc-$MIMALLOC_VERSION/CMakeLists.txt"
fi

TC_DIR="$TOOLCHAIN_ROOT/$TOOLCHAIN_NAME"
[[ -d $TC_DIR ]] || die "toolchain directory not found: $TC_DIR"
CC="$TC_DIR/bin/x86_64-linux-gcc"
CXX="$TC_DIR/bin/x86_64-linux-g++"
[[ -x $CC && -x $CXX ]] || die "musl C/C++ compilers not found under $TC_DIR/bin"
SYSROOT=$(find "$TC_DIR" -maxdepth 2 -type d -name sysroot | head -n 1)
[[ -n $SYSROOT ]] || die "toolchain sysroot not found"
HOST_TRIPLE=$("$CC" -dumpmachine)
[[ $HOST_TRIPLE == x86_64*buildroot*linux* ]] || die "unexpected cross compiler triple: $HOST_TRIPLE"
[[ -f $SYSROOT/usr/lib/libstdc++.a ]] || die "static libstdc++ is missing from the musl sysroot"

export CC CXX
export AR="$TC_DIR/bin/x86_64-linux-ar"
export RANLIB="$TC_DIR/bin/x86_64-linux-ranlib"
export NM="$TC_DIR/bin/x86_64-linux-nm"
export STRIP="$TC_DIR/bin/x86_64-linux-strip"
export CFLAGS="-O2 -fno-pie"
export CXXFLAGS="-O2 -fno-pie"
export LDFLAGS="-static -no-pie"
unset PKG_CONFIG_PATH PKG_CONFIG_SYSROOT_DIR LD_LIBRARY_PATH || true
export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"

log "toolchain: $TC_DIR ($("$CC" -dumpversion), host $HOST_TRIPLE)"
log "sysroot:   $SYSROOT"

# ---------------------------------------------------------------------------
# Dependencies: isolated musl prefix, static archives only.
# ---------------------------------------------------------------------------
# The build id covers every input that changes libcrypto's lock behaviour, so
# a cached prefix built with different Configure options is rebuilt instead of
# being reused just because the version string still matches.
openssl_build_id() {
    printf '%s\n' \
        "version=$OPENSSL_VERSION" \
        "target=$OPENSSL_TARGET" \
        "options=${OPENSSL_CONFIG_OPTIONS[*]}" \
        "cflags=$OPENSSL_CONFIGURE_CFLAGS" \
        "ldflags=$OPENSSL_CONFIGURE_LDFLAGS" \
        "cc=$CC" \
        | sha256sum | awk '{print $1}'
}

build_openssl() {
    local build_id
    build_id=$(openssl_build_id)
    if [[ -f $PREFIX/lib/libssl.a && -f $PREFIX/lib/libcrypto.a ]] \
        && [[ -f $PREFIX/.openssl-build-id ]] \
        && [[ -f $PREFIX/.openssl-configdata.pm ]] \
        && [[ $(<"$PREFIX/.openssl-build-id") == "$build_id" ]]; then
        return
    fi
    log "building OpenSSL $OPENSSL_VERSION (threads required, build id $build_id)"
    (
        cd "$SRC/openssl-$OPENSSL_VERSION"
        if [[ -f Makefile || -f configdata.pm ]]; then
            log "discarding cached OpenSSL objects (configure options changed)"
            if [[ -f Makefile ]]; then
                make clean >"$LOGS/openssl-clean.log" 2>&1 || true
            fi
            rm -f configdata.pm Makefile
            # Objects compiled against the previous configuration must never
            # be reused, including when "make clean" was unavailable.
            find . -name '*.o' -delete
        fi
        CFLAGS="$OPENSSL_CONFIGURE_CFLAGS" \
        CXXFLAGS="$OPENSSL_CONFIGURE_CFLAGS" \
        LDFLAGS="$OPENSSL_CONFIGURE_LDFLAGS" \
            ./Configure "$OPENSSL_TARGET" "${OPENSSL_CONFIG_OPTIONS[@]}" \
                --prefix="$PREFIX" --libdir=lib --openssldir="$PREFIX/ssl" \
                >"$LOGS/openssl-configure.log" 2>&1
        bash "$REPO_ROOT/tools/verify-static-locks.sh" --configdata-only configdata.pm
        make -j"$JOBS" >"$LOGS/openssl-build.log" 2>&1
        make install_sw >"$LOGS/openssl-install.log" 2>&1
    )
    [[ -f $PREFIX/lib/libssl.a && -f $PREFIX/lib/libcrypto.a ]] || die "OpenSSL static libraries were not installed"
    # The lock gate needs the Configure record of the library that was linked.
    # Keep it in the prefix: CI prunes src/ before saving the cache, so a later
    # run that reuses the cached prefix re-extracts a clean source tree with no
    # configdata.pm and could not verify anything.
    cp "$SRC/openssl-$OPENSSL_VERSION/configdata.pm" "$PREFIX/.openssl-configdata.pm"
    printf '%s\n' "$build_id" >"$PREFIX/.openssl-build-id"
    printf '%s\n' "$OPENSSL_VERSION" >"$PREFIX/.openssl-version"
}

build_libevent() {
    if [[ -f $PREFIX/lib/libevent.a && -f $PREFIX/lib/libevent_pthreads.a ]] \
        && [[ -f $PREFIX/.libevent-version ]] \
        && [[ $(<"$PREFIX/.libevent-version") == "$LIBEVENT_VERSION" ]]; then
        return
    fi
    log "building libevent $LIBEVENT_VERSION"
    (
        cd "$SRC/libevent-$LIBEVENT_VERSION"
        ./configure --host="$HOST_TRIPLE" --prefix="$PREFIX" \
            --disable-shared --enable-static --disable-openssl \
            --disable-samples --disable-libevent-regress --disable-debug-mode \
            >"$LOGS/libevent-configure.log" 2>&1
        make -j"$JOBS" >"$LOGS/libevent-build.log" 2>&1
        make install >"$LOGS/libevent-install.log" 2>&1
    )
    [[ -f $PREFIX/lib/libevent.a && -f $PREFIX/lib/libevent_pthreads.a ]] || die "libevent static libraries were not installed"
    printf '%s\n' "$LIBEVENT_VERSION" >"$PREFIX/.libevent-version"
}

build_curl() {
    local args=(
        --host="$HOST_TRIPLE" --build="$(uname -m)-pc-linux-gnu"
        --prefix="$PREFIX" --disable-shared --enable-static
        --with-openssl="$PREFIX"
        --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt
        --without-libpsl --without-libidn2 --without-brotli --without-zstd --without-zlib
        --without-libssh2 --without-nghttp2 --without-ngtcp2 --without-nghttp3 --without-quiche
        --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp
        --disable-pop3 --disable-imap --disable-smtp --disable-gopher --disable-mqtt --disable-ftp
        --disable-file --disable-manual --disable-docs --disable-ares --disable-proxy
        --disable-ipfs --disable-websockets
    )
    local build_id
    build_id=$(printf '%s\n' "$CURL_VERSION" "openssl=$OPENSSL_BUILD_ID" \
        "${args[@]}" | sha256sum | awk '{print $1}')
    if [[ -f $PREFIX/lib/libcurl.a && -f $PREFIX/.curl-build-id ]] \
        && [[ $(<"$PREFIX/.curl-build-id") == "$build_id" ]]; then
        return
    fi
    log "building curl $CURL_VERSION (HTTP/HTTPS + OpenSSL only)"
    (
        cd "$SRC/curl-$CURL_VERSION"
        if [[ -f Makefile ]]; then make distclean >/dev/null 2>&1 || true; fi
        ./configure "${args[@]}" >"$LOGS/curl-configure.log" 2>&1
        make -j"$JOBS" >"$LOGS/curl-build.log" 2>&1
        make install >"$LOGS/curl-install.log" 2>&1
    )
    [[ -f $PREFIX/lib/libcurl.a ]] || die "curl static library was not installed"
    grep -q 'supported_protocols="HTTP HTTPS"' "$PREFIX/lib/pkgconfig/libcurl.pc" \
        || die "libcurl was built with protocol handlers beyond HTTP/HTTPS"
    printf '%s\n' "$build_id" >"$PREFIX/.curl-build-id"
}

OPENSSL_BUILD_ID=$(openssl_build_id)
log "OpenSSL build id: $OPENSSL_BUILD_ID"
build_mimalloc() {
    if [[ -f $PREFIX/lib/mimalloc.o && -f $PREFIX/.mimalloc-version ]] \
        && [[ $(<"$PREFIX/.mimalloc-version") == "$MIMALLOC_VERSION" ]]; then
        return
    fi
    log "building mimalloc $MIMALLOC_VERSION (static override object, musl)"
    local dir="$BUILD/mimalloc"
    rm -rf "$dir"
    cmake -S "$SRC/mimalloc-$MIMALLOC_VERSION" -B "$dir" -G Ninja \
        -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-O2 -fno-pie" \
        -DMI_LIBC_MUSL=ON -DMI_OVERRIDE=ON -DMI_BUILD_SHARED=OFF \
        -DMI_BUILD_STATIC=OFF -DMI_BUILD_OBJECT=ON -DMI_BUILD_TESTS=OFF \
        -DMI_SECURE=OFF -DMI_DEBUG_FULL=OFF \
        >"$LOGS/mimalloc-configure.log" 2>&1
    cmake --build "$dir" -j "$JOBS" >"$LOGS/mimalloc-build.log" 2>&1
    local object
    object=$(find "$dir" -name 'mimalloc*.o' | head -n 1)
    [[ -n $object ]] || die "mimalloc object was not produced"
    install -m 0644 "$object" "$PREFIX/lib/mimalloc.o"
    printf '%s\n' "$MIMALLOC_VERSION" >"$PREFIX/.mimalloc-version"
}

build_openssl
build_libevent
build_curl
MIMALLOC_LINK=""
if ((MIMALLOC)); then
    build_mimalloc
    MIMALLOC_LINK="$PREFIX/lib/mimalloc.o"
fi

# nlohmann/json is header-only. Stage the host 3.12.0 header with a minimal
# CMake package so CMake cannot accidentally resolve the host glibc package.
if [[ ! -f $PREFIX/lib/cmake/nlohmann_json/nlohmann_jsonConfig.cmake ]]; then
    log "staging nlohmann_json 3.12.0 (header-only)"
    mkdir -p "$PREFIX/include" "$PREFIX/lib/cmake/nlohmann_json"
    rm -rf "$PREFIX/include/nlohmann"
    cp -a /usr/include/nlohmann "$PREFIX/include/nlohmann"
    cat >"$PREFIX/lib/cmake/nlohmann_json/nlohmann_jsonConfig.cmake" <<'EOF'
get_filename_component(_nlohmann_prefix "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
if(NOT TARGET nlohmann_json::nlohmann_json)
  add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
  set_target_properties(nlohmann_json::nlohmann_json PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${_nlohmann_prefix}/include")
endif()
set(nlohmann_json_FOUND TRUE)
EOF
    cat >"$PREFIX/lib/cmake/nlohmann_json/nlohmann_jsonConfigVersion.cmake" <<'EOF'
set(PACKAGE_VERSION "3.12.0")
if(PACKAGE_FIND_VERSION VERSION_LESS_EQUAL PACKAGE_VERSION)
  set(PACKAGE_VERSION_COMPATIBLE TRUE)
else()
  set(PACKAGE_VERSION_COMPATIBLE FALSE)
endif()
if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
  set(PACKAGE_VERSION_EXACT TRUE)
endif()
EOF
fi

# ---------------------------------------------------------------------------
# Cross toolchain file and CMake build. No repository CMake changes needed.
# ---------------------------------------------------------------------------
TOOLCHAIN_FILE="$ROOT/toolchain-musl.cmake"
cat >"$TOOLCHAIN_FILE" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER "$CC")
set(CMAKE_CXX_COMPILER "$CXX")
set(CMAKE_FIND_ROOT_PATH "$PREFIX" "$SYSROOT")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_C_FLAGS_INIT "-O2 -fno-pie -pthread -ffile-prefix-map=$ROOT=mtdd-static -ffile-prefix-map=$REPO_ROOT=mtdd")
set(CMAKE_CXX_FLAGS_INIT "-O2 -fno-pie -pthread -ffile-prefix-map=$ROOT=mtdd-static -ffile-prefix-map=$REPO_ROOT=mtdd")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -no-pie -pthread -Wl,--build-id=none $MIMALLOC_LINK")
EOF

BUILD_DIR="$BUILD/mtdd"
log "configuring mtdd (Release, BUILD_TESTING=OFF, static musl)"
rm -rf "$BUILD_DIR"
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS_RELEASE="-O2 -DNDEBUG" \
    -DCMAKE_PREFIX_PATH="$PREFIX" \
    -DOPENSSL_ROOT_DIR="$PREFIX" \
    -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DPKG_CONFIG_EXECUTABLE=/usr/bin/pkg-config \
    -DPKG_CONFIG_ARGN=--static \
    -DBUILD_TESTING=OFF \
    >"$LOGS/cmake-configure.log" 2>&1
cmake --build "$BUILD_DIR" -j "$JOBS" >"$LOGS/cmake-build.log" 2>&1

BIN="$BUILD_DIR/mtdd"
[[ -x $BIN ]] || die "mtdd executable was not produced"

# gcc/ld diagnostics from the mtdd build must not reference host paths.
if grep -E '/usr/lib/x86_64-linux-gnu|/usr/include/(openssl|curl|event2)' "$LOGS/cmake-configure.log" >/dev/null; then
    die "CMake resolved host glibc dependency paths; refusing to package"
fi
LINK_COMMAND=$(ninja -C "$BUILD_DIR" -t commands mtdd | tail -n 1)
if grep -E '/usr/(lib|include|local)' <<<"$LINK_COMMAND"; then
    die "final link command references host /usr paths; refusing to package"
fi

# ---------------------------------------------------------------------------
# Static-binary verification (hard gate).
# ---------------------------------------------------------------------------
INSPECTION="$OUT/static-inspection.txt"
{
    echo "file: $(file -b "$BIN")"
    echo
    echo "readelf -l (program headers):"
    readelf -lW "$BIN"
    echo
    echo "readelf -d (dynamic section):"
    readelf -dW "$BIN" 2>&1 || true
    echo
    echo "objdump -p (dynamic objects):"
    objdump -p "$BIN" | sed -n '/Dynamic Section/,/^$/p'
    echo
    echo "resolved shared objects (ldd):"
    ldd "$BIN" 2>&1 || true
} >"$INSPECTION"

FILE_DESC=$(file -b "$BIN")
[[ $FILE_DESC == *"ELF 64-bit"* ]] || die "not an ELF64 binary: $FILE_DESC"
[[ $FILE_DESC == *"x86-64"* ]] || die "not x86-64: $FILE_DESC"
[[ $FILE_DESC == *"statically linked"* ]] || die "file(1) does not report statically linked: $FILE_DESC"
[[ $(readelf -hW "$BIN" | awk '/Type:/{print $2}') == EXEC ]] \
    || die "binary is not a non-PIE ET_EXEC"

# Capture first: piping readelf into grep -q can trigger SIGPIPE under pipefail.
PROGRAM_HEADERS=$(readelf -lW "$BIN")
DYNAMIC_SECTION=$(readelf -dW "$BIN" 2>&1 || true)
DYNAMIC_OBJECTS=$(objdump -p "$BIN")
if grep -q 'INTERP' <<<"$PROGRAM_HEADERS"; then
    die "binary contains a PT_INTERP program header"
fi
if grep -q 'NEEDED' <<<"$DYNAMIC_SECTION"; then
    die "binary contains DT_NEEDED entries"
fi
if grep -q '^  NEEDED' <<<"$DYNAMIC_OBJECTS"; then
    die "objdump reports NEEDED entries"
fi
if grep -aE 'GLIBC_[0-9]' "$BIN" >/dev/null; then
    die "binary references glibc-versioned symbols"
fi
grep -aF -- '/etc/ssl/certs/ca-certificates.crt' "$BIN" >/dev/null \
    || die "curl CA bundle default is missing from the binary"

# Hard packaging gate: a no-threads libcrypto links CRYPTO_THREAD_* as no-ops
# and crashes concurrent handshakes. Verify the linked code, not just inputs.
log "verifying OpenSSL thread locks in the linked binary"
bash "$REPO_ROOT/tools/verify-static-locks.sh" \
    "$BIN" "$PREFIX/.openssl-configdata.pm" | tee "$OUT/lock-gate.txt"

mkdir -p "$(dirname "$COPY")"
cp "$BIN" "$OUT/mtdd"
cp "$BIN" "$COPY"
cmp -s "$BIN" "$COPY" || die "artifact copy does not match the built binary"
BIN="$COPY"

if ((VERIFY)); then
    log "running binary/API checks against the static artifact"
    VERSION_OUTPUT=$("$BIN" --version)
    [[ $VERSION_OUTPUT == "mtdd 0.1.0" ]] || die "unexpected --version output: $VERSION_OUTPUT"

    CHECK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mtdd-static-check.XXXXXX")
    trap 'rm -rf "$CHECK_DIR"' EXIT
    cat >"$CHECK_DIR/config.json" <<'EOF'
{
  "proxy_host": "127.0.0.1",
  "proxy_port": 24443,
  "control_host": "127.0.0.1",
  "control_port": 29090,
  "tls_domain": "example.org",
  "ad_tag": "00112233445566778899aabbccddeeff",
  "users_path": "users.json",
  "max_connections": 16,
  "max_handshakes": 8,
  "shutdown_timeout_seconds": 1
}
EOF
    CHECK_OUTPUT=$("$BIN" --config "$CHECK_DIR/config.json" --check-config)
    [[ $CHECK_OUTPUT == "configuration valid (syntax and static limits only)" ]] \
        || die "unexpected --check-config output: $CHECK_OUTPUT"

    log "probing libcurl runtime defaults used by mtdd"
    cat >"$OUT/curl-probe.cpp" <<'EOF'
#include <curl/curl.h>
#include <cstdio>
int main() {
    const auto* version = curl_version_info(CURLVERSION_NOW);
    std::printf("curl=%s ssl=%s cainfo=%s\n", version->version, version->ssl_version,
                version->cainfo ? version->cainfo : "(none)");
    std::printf("protocols:");
    for (const char* const* protocol = version->protocols; *protocol; ++protocol)
        std::printf(" %s", *protocol);
    std::printf("\n");
    return 0;
}
EOF
    PROBE_CFLAGS=$(PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" pkg-config --static --cflags libcurl)
    PROBE_LIBS=$(PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" pkg-config --static --libs libcurl)
    # shellcheck disable=SC2086
    "$CXX" -O2 -static -no-pie $PROBE_CFLAGS "$OUT/curl-probe.cpp" $PROBE_LIBS -o "$OUT/curl-probe"
    PROBE_OUTPUT=$("$OUT/curl-probe")
    grep -q 'cainfo=/etc/ssl/certs/ca-certificates.crt' <<<"$PROBE_OUTPUT" \
        || die "static libcurl does not expose the system CA bundle default"
    grep -q 'protocols: http https$' <<<"$PROBE_OUTPUT" \
        || die "static libcurl exposes unexpected protocols: $PROBE_OUTPUT"
    printf '%s\n' "$PROBE_OUTPUT"

    python3 "$REPO_ROOT/tests/integration/control_smoke.py" "$BIN" \
        >"$LOGS/control-smoke.log" 2>&1 || die "control_smoke.py failed; see $LOGS/control-smoke.log"
    cat "$LOGS/control-smoke.log"

    # Prove the executable does not rely on inherited environment/loader paths.
    env -i "$BIN" --version >/dev/null || die "binary failed with an empty environment"
    rm -rf "$CHECK_DIR"
    trap - EXIT
fi

SHA256=$(sha256sum "$BIN" | awk '{print $1}')
SIZE=$(stat -c %s "$BIN")
{
    echo "artifact=$OUT/mtdd"
    echo "copy=$COPY"
    echo "sha256=$SHA256"
    echo "size=$SIZE"
    echo "file=$FILE_DESC"
    echo "toolchain=$TOOLCHAIN_NAME"
    echo "openssl=$OPENSSL_VERSION"
    echo "openssl_build_id=$OPENSSL_BUILD_ID"
    echo "libevent=$LIBEVENT_VERSION"
    echo "curl=$CURL_VERSION"
    echo "nlohmann_json=3.12.0"
} | tee "$OUT/build-info.txt"

log "static build verified: $OUT/mtdd"
