#!/usr/bin/env bash
# Shared interactive input. Values always come from the current SSH operator.
INPUTS_BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
prompt_value() {
    local kind=$1 prompt=$3
    local -n field=$2
    while true; do
        read -e -r -p "$prompt" field </dev/tty || die 'Input cancelled.'
        if python3 - "$INPUTS_BASE" "$kind" "$field" "$INBOUND" <<'PY'
import ipaddress, sys
sys.path.insert(0, sys.argv[1])
from config import DEFAULTS, validate
try:
    if sys.argv[2] == 'domain':
        validate(dict(DEFAULTS, domain=sys.argv[3]))
    else:
        ipaddress.IPv4Address(sys.argv[3])
        if sys.argv[2] == 'outbound' and sys.argv[3] == sys.argv[4]:
            raise ValueError('The second IPv4 must differ from the incoming address.')
except ValueError as exc:
    print(f'Invalid value: {exc} Please enter this field again.', file=sys.stderr)
    raise SystemExit(1)
PY
        then break; fi
    done
}
collect_inputs() {
    if [[ -z "$DOMAIN" || -z "$INBOUND" || -z "$OUTBOUND" ]]; then
        [[ -r /dev/tty ]] || die 'A TTY is required for setup. Use ssh -t or pass --domain, --inbound and --outbound.'
        printf '\nSetup needs a domain with DNS A pointing to the incoming IP, and two assigned public IPv4 addresses.\n'
        printf 'Currently assigned IPv4 addresses:\n'
        ip -o -4 addr show scope global
        if [[ -z "$DOMAIN" ]]; then prompt_value domain DOMAIN 'Domain (e.g. vpn.example.com): '; fi
        if [[ -z "$INBOUND" ]]; then prompt_value inbound INBOUND 'Incoming public IPv4 (TCP 443, domain DNS A): '; fi
        if [[ -z "$OUTBOUND" ]]; then prompt_value outbound OUTBOUND 'Second public IPv4 (outgoing traffic): '; fi
    fi
    [[ -n "$DOMAIN" && -n "$INBOUND" && -n "$OUTBOUND" ]] || die 'Domain and both public IPv4 addresses are required.'
}
