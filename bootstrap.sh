#!/usr/bin/env bash
# Download a complete immutable revision, verify its manifest, then preflight/install.
# shellcheck source-path=SCRIPTDIR
set -Eeuo pipefail
umask 077
REPOSITORY=grislytoe/vless-server-kit
REVISION=${VLESS_KIT_REVISION:-}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || die 'Set VLESS_KIT_REVISION to the reviewed full commit SHA.'
[[ $EUID -eq 0 ]] || die 'Run with sudo or from a root SSH session.'
for cmd in curl tar sha256sum python3; do command -v "$cmd" >/dev/null || die "Missing prerequisite: $cmd"; done
WORK=$(mktemp -d /tmp/vless-kit.XXXXXXXX)
trap 'rm -rf -- "$WORK"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 180 --retry 3 \
    "https://codeload.github.com/$REPOSITORY/tar.gz/$REVISION" -o "$WORK/kit.tar.gz"
tar -xzf "$WORK/kit.tar.gz" --strip-components=1 -C "$WORK"
cd "$WORK"
sha256sum --strict -c SHA256SUMS
DOMAIN=""; INBOUND=""; OUTBOUND=""
for arg in "$@"; do
    case "$arg" in
        --domain=*) DOMAIN=${arg#--domain=} ;;
        --inbound=*) INBOUND=${arg#--inbound=} ;;
        --outbound=*) OUTBOUND=${arg#--outbound=} ;;
        --archive=*) ;;
        *) die "Unknown option: $arg" ;;
    esac
done
# shellcheck source=inputs.sh
source "$WORK/inputs.sh"
collect_inputs
args=("$@" "--domain=$DOMAIN" "--inbound=$INBOUND" "--outbound=$OUTBOUND")
bash install.sh --check "${args[@]}"
bash install.sh --install "${args[@]}"
