#!/usr/bin/env bash
# A complete function is parsed before execution when launched through curl | bash.
# shellcheck source-path=SCRIPTDIR
main() {
    set -Eeuo pipefail
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    unset PYTHONPATH PYTHONHOME
    umask 077
    die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
    UPDATE=false
    for arg in "$@"; do
        case "$arg" in
            --update) UPDATE=true ;;
            *) die "Unknown option: $arg (supported: --update)" ;;
        esac
    done
    [[ $EUID -eq 0 ]] || die 'Run through sudo bash or from a root SSH session.'
    [[ -d /run/systemd/system ]] || die 'A full Ubuntu/Debian VPS with systemd is required.'
    if [[ "$UPDATE" == true ]]; then
        [[ -f /var/lib/vless-optimized/settings.json ]] || die 'No managed VPN found; update refused.'
    fi
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
    # Release snapshot: promoted only after real Linux service/browser checks pass.
    REVISION=284ccae8e192ec87600d5d3d1f6a109ef4964d63
    ARCHIVE_SHA256=29d1c4035c5780304c8cd60b452d6c33c060251164627e5da78f0c44f2c06dbe
    WORK=$(mktemp -d /tmp/vless-release.XXXXXXXX)
    trap '[[ "$WORK" == /tmp/vless-release.* ]] && rm -rf -- "$WORK"' EXIT
    curl --proto '=https' --tlsv1.2 -fSL --retry 3 --connect-timeout 15 --max-time 180 \
        "https://codeload.github.com/grislytoe/vless-server-kit/tar.gz/$REVISION" -o "$WORK/kit.tar.gz"
    printf '%s  %s\n' "$ARCHIVE_SHA256" "$WORK/kit.tar.gz" | sha256sum -c -
    tar -xzf "$WORK/kit.tar.gz" --strip-components=1 -C "$WORK"
    cd "$WORK"
    sha256sum --strict -c SHA256SUMS
    if [[ "$UPDATE" == true ]]; then
        bash install.sh --update
        return
    fi
    DOMAIN=""; INBOUND=""; OUTBOUND=""
    # shellcheck source=inputs.sh
    source "$WORK/inputs.sh"
    collect_inputs
    args=("--domain=$DOMAIN" "--inbound=$INBOUND" "--outbound=$OUTBOUND")
    bash install.sh --check "${args[@]}"
    bash install.sh --install "${args[@]}"
}
main "$@"
