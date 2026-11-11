"""Verify the local REALITY target through its required PROXY header and TLS."""
import argparse
import socket
import ssl


def check(domain, port):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
        raw.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 12345 443\r\n')
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            if tls.selected_alpn_protocol() != 'h2':
                raise RuntimeError('Fallback did not negotiate H2.')
    print('Verified local fallback certificate, TLS 1.3 and H2.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', required=True)
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    check(args.domain, args.port)
