#!/usr/bin/env bash
# Build and run against a real LEZ sequencer.
#
# Three things stand between a clean clone and a running stack, none of them
# ours:
#
#   1. The wallet links PC/SC for Keycard, so the build needs libpcsclite.
#      Nix's pkg-config wrapper ignores PKG_CONFIG_PATH and reads the
#      target-suffixed variable instead.
#   2. LEZ's test fixtures expect a Bedrock node binary next to their own
#      manifest. No published Bedrock release matches the revision LEZ pins,
#      so their resolver compiles the L1 from source in Docker — once, then
#      cached.
#   3. That libpcsclite wants a newer glibc than the Rust toolchain links
#      against, so the binary runs under the newer loader. Harmless: glibc is
#      backward compatible.
#
# Everything is discovered at run time. No store paths are hardcoded, and
# nothing in the LEZ checkout is modified beyond the gitignored directory its
# own resolver writes to.
set -euo pipefail

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v cargo  >/dev/null || die "cargo is not on PATH"
command -v nix    >/dev/null || die "nix is not on PATH (needed for libpcsclite)"
command -v docker >/dev/null || die "docker is not on PATH (Bedrock runs in it)"
docker info >/dev/null 2>&1  || die "the docker daemon is not reachable"

# --- 1. libpcsclite, for the wallet's Keycard support ----------------------
say "resolving libpcsclite"
pcsc_dev=$(nix build --no-link --print-out-paths 'nixpkgs#pcsclite.dev')
pcsc_lib=$(nix build --no-link --print-out-paths 'nixpkgs#pcsclite.lib')
export PKG_CONFIG_PATH_x86_64_unknown_linux_gnu="$pcsc_dev/lib/pkgconfig"
pkg-config --exists libpcsclite || die "libpcsclite still not visible to pkg-config"

# --- 2. build --------------------------------------------------------------
say "building"
cargo build --release

bin=target/release/ostrakon-testnet
[ -x "$bin" ] || die "$bin was not produced"

# --- 3. the Bedrock node, where LEZ's fixtures look for it -----------------
# Ask cargo where test_fixtures came from rather than guessing the checkout.
lez_root=$(cargo metadata --format-version 1 2>/dev/null | python3 -c '
import json,sys,pathlib
m=json.load(sys.stdin)
for p in m["packages"]:
    if p["name"]=="test_fixtures":
        print(pathlib.Path(p["manifest_path"]).parent.parent); break
else:
    sys.exit(1)') || die "test_fixtures is not in the dependency graph"

resolved="$lez_root/bedrock/.resolved/logos-blockchain-node"
if [ -x "$resolved" ]; then
    say "Bedrock node already resolved"
else
    say "resolving the Bedrock node (compiles the L1 in Docker; several minutes, once)"
    bash "$lez_root/bedrock/tools/resolve_bedrock_node_in_docker.sh"
    [ -x "$resolved" ] || die "the resolver did not produce $resolved"
fi

# --- 4. run under a loader that satisfies libpcsclite ----------------------
# pcsclite is built against a newer glibc than the toolchain links; take that
# glibc from pcsclite's own closure so the two always agree.
glibc=$(nix-store --query --references "$pcsc_lib" | grep -m1 'glibc-[0-9]') \
    || die "could not find the glibc libpcsclite was built against"

# Keep whatever the binary already resolves (libgcc_s and friends).
own=$(ldd "$bin" 2>/dev/null | awk '{print $3}' | grep '^/nix' \
      | xargs -r -n1 dirname | sort -u | paste -sd: -)

# The stack logs whole transactions at info level, which buries our own
# output. Keep warnings and above unless the caller asks for more.
export RUST_LOG="${RUST_LOG:-warn}"

# LEZ's stack prints whole transactions to stdout. Keep the lot in a log and
# show only our own lines, which the binary writes to stderr.
log=${OSTRAKON_LOG:-run.log}
say "starting the stack (full output in $log)"
set +e
"$glibc/lib/ld-linux-x86-64.so.2" \
    --library-path "$glibc/lib:$pcsc_lib/lib:$own" \
    "$bin" "$@" 2> >(tee -a "$log" | grep --line-buffered '^ostrakon| ' | sed 's/^ostrakon| //' >&2) \
    > "$log"
status=$?
set -e
exit $status
