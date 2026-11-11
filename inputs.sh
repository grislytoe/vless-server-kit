#!/usr/bin/env bash
# Shared interactive input. Values always come from the current SSH operator.
collect_inputs() {
    if [[ -z "$DOMAIN" || -z "$INBOUND" || -z "$OUTBOUND" ]]; then
        [[ -r /dev/tty ]] || die 'A TTY is required for setup. Use ssh -t or pass --domain, --inbound and --outbound.'
        printf '\nSetup needs a domain with DNS A pointing to the incoming IP, and two assigned public IPv4 addresses.\n'
        printf 'Currently assigned IPv4 addresses:\n'
        ip -o -4 addr show scope global
        if [[ -z "$DOMAIN" ]]; then read -r -p 'Domain (e.g. vpn.example.com): ' DOMAIN </dev/tty || die 'Input cancelled.'; fi
        if [[ -z "$INBOUND" ]]; then read -r -p 'Incoming public IPv4 (TCP 443, domain DNS A): ' INBOUND </dev/tty || die 'Input cancelled.'; fi
        if [[ -z "$OUTBOUND" ]]; then read -r -p 'Second public IPv4 (outgoing traffic): ' OUTBOUND </dev/tty || die 'Input cancelled.'; fi
    fi
    [[ -n "$DOMAIN" && -n "$INBOUND" && -n "$OUTBOUND" ]] || die 'Domain and both public IPv4 addresses are required.'
}
