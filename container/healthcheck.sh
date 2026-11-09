#!/usr/bin/env bash
# HTTP discovery only; authenticated transaction readiness is tested separately.
set -Eeuo pipefail
exec 3<>/dev/tcp/127.0.0.1/7474
printf 'GET / HTTP/1.0\r\nHost: localhost\r\nAccept: application/json\r\n\r\n' >&3
read -r -t 4 status <&3
[[ $status == 'HTTP/1.1 200 '* || $status == 'HTTP/1.0 200 '* ]]
