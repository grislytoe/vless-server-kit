#!/usr/bin/env bash
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME
umask 022
[[ $EUID -eq 0 ]] || { printf 'Run runtime.sh as root.\n' >&2; exit 1; }
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUNTIME=/opt/vless-runtime/gunicorn-27.0.0
install -d -m 755 -o root -g root /opt/vless-runtime
python3 -m venv --system-site-packages "$RUNTIME"
"$RUNTIME/bin/python" -m pip --isolated install --disable-pip-version-check --no-deps \
    --only-binary=:all: --require-hashes --index-url https://pypi.org/simple -r "$BASE/requirements-server.txt"
"$RUNTIME/bin/python" -c 'import gunicorn; assert gunicorn.__version__ == "27.0.0"'
