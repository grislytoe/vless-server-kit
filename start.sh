#!/usr/bin/env bash
# A complete function is parsed before execution when launched through curl | bash.
# shellcheck source-path=SCRIPTDIR
main() {
    set -Eeuo pipefail
    umask 077
    die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
    [[ $EUID -eq 0 ]] || die 'Run through sudo bash or from a root SSH session.'
    [[ -d /run/systemd/system ]] || die 'A full Ubuntu/Debian VPS with systemd is required.'
    # shellcheck source=/dev/null
    source /etc/os-release
    case "$ID:$VERSION_ID" in
        ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
        *) die "Unsupported operating system: $ID $VERSION_ID" ;;
    esac
    case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) die 'x86_64 or ARM64 is required.' ;; esac
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v curl >/dev/null || ! command -v python3 >/dev/null || \
       ! command -v ip >/dev/null || ! command -v flock >/dev/null || \
       [[ ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
        apt-get update
        apt-get install -y ca-certificates curl python3 iproute2 util-linux tar coreutils
    fi
    # Release pointer: updated only after the real Linux service checks pass.
    REVISION=af55eabbebe7eeae66b1a714d33fd0be6f58cd59
    ARCHIVE_SHA256=f0f4167104594d5b173075535156f69bca9c7d37078dd16d98a596552b8e08ae
    WORK=$(mktemp -d /tmp/vless-release.XXXXXXXX)
    trap '[[ "$WORK" == /tmp/vless-release.* ]] && rm -rf -- "$WORK"' EXIT
    curl --proto '=https' --tlsv1.2 -fSL --retry 3 --connect-timeout 15 --max-time 180 \
        "https://codeload.github.com/grislytoe/vless-server-kit/tar.gz/$REVISION" -o "$WORK/kit.tar.gz"
    printf '%s  %s\n' "$ARCHIVE_SHA256" "$WORK/kit.tar.gz" | sha256sum -c -
    tar -xzf "$WORK/kit.tar.gz" --strip-components=1 -C "$WORK"
    cd "$WORK"
    sha256sum --strict -c SHA256SUMS
    DOMAIN=""; INBOUND=""; OUTBOUND=""
    # shellcheck source=inputs.sh
    source "$WORK/inputs.sh"
    collect_inputs
    args=("--domain=$DOMAIN" "--inbound=$INBOUND" "--outbound=$OUTBOUND")
    bash install.sh --check "${args[@]}"
    bash install.sh --install "${args[@]}"
}
main "$@"
