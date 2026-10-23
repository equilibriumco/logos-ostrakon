#!/usr/bin/env bash
# Build and run against a real LEZ sequencer.
#
# Nothing in LEZ is modified. Its test fixtures come in as a pinned git
# dependency and bring their own Bedrock resolver. What this script adds is
# the few pieces that resolver and the wallet need, which differ by platform.
#
# The wallet links PC/SC for Keycard. On macOS that is a system framework, so
# the build finds it and the binary runs as built. On Linux it is libpcsclite,
# and two things follow from taking it out of nixpkgs: Nix's pkg-config
# wrapper ignores PKG_CONFIG_PATH and reads a target-suffixed variable
# instead, and that libpcsclite wants a newer glibc than the Rust toolchain
# links against, so the binary runs under the newer loader. Harmless, since
# glibc is backward compatible.
#
# Both platforms need the Bedrock node, which LEZ's fixtures run in a
# container. No published Bedrock release matches the revision LEZ pins, so
# their resolver compiles the L1 from source, once, then caches it.
#
# Everything is discovered at run time. No store paths are hardcoded, and
# nothing in the LEZ checkout is modified beyond the gitignored directory its
# own resolver writes to.
set -euo pipefail

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Relative paths below are this workspace's, not the caller's.
cd "$(dirname "${BASH_SOURCE[0]}")"

command -v cargo  >/dev/null || die "cargo is not on PATH"
command -v rustc  >/dev/null || die "rustc is not on PATH"
command -v docker >/dev/null || die "docker is not on PATH (Bedrock runs in a container)"
docker info >/dev/null 2>&1  || die "the container daemon is not reachable"

# Docker and Podman report the daemon under different info schemas, which is
# also what tells the two apart: Podman's CLI answers to `docker`.
if arch=$(docker info --format '{{.Architecture}}' 2>/dev/null); then
    engine=docker
elif arch=$(docker info --format '{{.Host.Arch}}' 2>/dev/null); then
    engine=podman
else
    die "could not read the container daemon's architecture"
fi

# LEZ's fixtures publish Bedrock's port as host port 0, which Docker Compose
# reads as "pick a free one". Podman rejects 0 as out of range and the
# container never starts, so this needs Docker until LEZ stops asking for 0.
if [ "$engine" = podman ]; then
    die "the container engine is Podman. LEZ's fixtures ask compose for host port 0, which Podman rejects, so Bedrock cannot start. This needs Docker."
fi

os=$(uname -s)
triple=$(rustc -vV | awk '/^host:/ { print $2 }')

# --- 1. libpcsclite, for the wallet's Keycard support ----------------------
case "$os" in
Darwin)
    # PC/SC is a system framework here, so there is nothing to resolve.
    ;;
Linux)
    command -v nix >/dev/null || die "nix is not on PATH (needed for libpcsclite)"
    say "resolving libpcsclite"
    pcsc_dev=$(nix build --no-link --print-out-paths 'nixpkgs#pcsclite.dev')
    pcsc_lib=$(nix build --no-link --print-out-paths 'nixpkgs#pcsclite.lib')
    export "PKG_CONFIG_PATH_${triple//-/_}=$pcsc_dev/lib/pkgconfig"
    pkg-config --exists libpcsclite || die "libpcsclite still not visible to pkg-config"
    ;;
*)
    die "unsupported platform: $os"
    ;;
esac

# --- 2. build --------------------------------------------------------------
say "building"
cargo build --release

bin=target/release/ostrakon-testnet
[ -x "$bin" ] || die "$bin was not produced"

# --- 3. the Bedrock node, where LEZ's fixtures look for it -----------------
# Ask cargo where test_fixtures came from rather than guessing the checkout.
# It is a git dependency, so this is the pinned revision under CARGO_HOME, not
# anyone's own LEZ clone. A clone at another revision resolves another Bedrock
# node, and the fixtures reject it.
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
    # LEZ's own resolve_bedrock_node_in_docker.sh probes the daemon
    # architecture itself and exits when the probe fails. The platform is
    # already known here, so call LEZ's resolver with it directly.
    case "$arch" in
        amd64|x86_64)  docker_platform=linux/amd64; target_platform=linux-x86_64  ;;
        arm64|aarch64) docker_platform=linux/arm64; target_platform=linux-aarch64 ;;
        *) die "unsupported container architecture: $arch" ;;
    esac

    say "resolving the Bedrock node (compiles the L1 in a container; several minutes, once)"
    image=lez-bedrock-resolver:local
    docker build \
        --platform "$docker_platform" \
        --file "$lez_root/bedrock/tools/resolver.Dockerfile" \
        --tag "$image" \
        "$lez_root/bedrock/tools"

    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    resolver_home=/tmp/lez-bedrock-resolver-home
    mkdir -p "$cargo_home/registry" "$cargo_home/git" "$HOME/.cache/logos/blockchain"

    docker run --rm \
        --platform "$docker_platform" \
        --user "$(id -u):$(id -g)" \
        --volume "$lez_root:$lez_root" \
        --volume "$cargo_home/registry:/cargo/registry" \
        --volume "$cargo_home/git:/cargo/git" \
        --volume "$HOME/.cache/logos/blockchain:$resolver_home/.cache/logos/blockchain" \
        --env CARGO_HOME=/cargo \
        --env HOME="$resolver_home" \
        --env XDG_CACHE_HOME="$resolver_home/.cache" \
        --workdir "$lez_root" \
        --env RUSTFLAGS=-A\ single-use-lifetimes \
        --env RISC0_DEV_MODE=1 \
        "$image" \
        python3 bedrock/tools/resolve_bedrock_node.py \
            --target-platform "$target_platform"

    [ -x "$resolved" ] || die "the resolver did not produce $resolved"
fi

# --- 4. run ----------------------------------------------------------------
launch=("$bin")
if [ "$os" = Linux ]; then
    # pcsclite is built against a newer glibc than the toolchain links; take
    # that glibc from pcsclite's own closure so the two always agree.
    glibc=$(nix-store --query --references "$pcsc_lib" | grep -m1 'glibc-[0-9]') \
        || die "could not find the glibc libpcsclite was built against"
    case "$triple" in
        x86_64-*)  loader=ld-linux-x86-64.so.2  ;;
        aarch64-*) loader=ld-linux-aarch64.so.1 ;;
        *) die "no loader known for $triple" ;;
    esac

    # Keep whatever the binary already resolves (libgcc_s and friends).
    own=$(ldd "$bin" 2>/dev/null | awk '{print $3}' | grep '^/nix' \
          | xargs -r -n1 dirname | sort -u | paste -sd: -)

    launch=("$glibc/lib/$loader" --library-path "$glibc/lib:$pcsc_lib/lib:$own" "$bin")
fi

# The stack logs whole transactions at info level, which buries our own
# output. Keep warnings and above unless the caller asks for more.
export RUST_LOG="${RUST_LOG:-warn}"

# LEZ's stack prints whole transactions to stdout. Keep the lot in a log and
# show only our own lines, which the binary writes to stderr.
log=${OSTRAKON_LOG:-run.log}
say "starting the stack (full output in $log)"
: > "$log"
set +e
"${launch[@]}" "$@" \
    2> >(tee -a "$log" | grep --line-buffered '^ostrakon| ' | sed 's/^ostrakon| //' >&2) \
    >> "$log"
status=$?
set -e
exit $status
