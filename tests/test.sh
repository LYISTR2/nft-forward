#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="${ROOT_DIR}/nft-forward.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

test_static_and_cli() {
    bash -n "${SCRIPT}"
    if command -v shellcheck >/dev/null 2>&1; then
        shellcheck -x "${SCRIPT}"
    fi

    "${SCRIPT}" --help | grep -q -- '--traffic'

    set +e
    "${SCRIPT}" --unknown >/tmp/nft-forward-test-unknown.out 2>&1
    local rc=$?
    set -e
    [[ $rc -eq 2 ]] || fail "unknown option exit code is ${rc}, want 2"

    timeout 2 "${SCRIPT}" </dev/null >/tmp/nft-forward-test-eof.out 2>&1
    grep -q '输入结束，退出' /tmp/nft-forward-test-eof.out || fail "EOF did not exit cleanly"
    rm -f /tmp/nft-forward-test-unknown.out /tmp/nft-forward-test-eof.out
    pass "static checks and CLI/EOF handling"
}

test_namespace_runtime() {
    command -v unshare >/dev/null 2>&1 || fail "unshare is required"
    command -v nft >/dev/null 2>&1 || fail "nft is required"
    command -v ip >/dev/null 2>&1 || fail "iproute2 is required"
    command -v python3 >/dev/null 2>&1 || fail "python3 is required"

    local tmp
    tmp=$(mktemp -d /tmp/nft-forward-test.XXXXXX)
    trap 'rm -rf "${tmp:-}"' RETURN
    mkdir -p "${tmp}/etc/nftables.d/backups" "${tmp}/etc/sysctl.d" "${tmp}/etc/logrotate.d" "${tmp}/var/log" "${tmp}/bin"

    cat > "${tmp}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat > "${tmp}/bin/sysctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -n && "${2:-}" == net.ipv4.ip_forward ]]; then echo 1; fi
exit 0
EOF
    cat > "${tmp}/bin/modprobe" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat > "${tmp}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
    cat > "${tmp}/bin/ufw" <<'EOF'
#!/usr/bin/env bash
echo inactive
exit 0
EOF
    chmod +x "${tmp}/bin/"*

    local test_script="${tmp}/runtime.sh"
    sed \
        -e "s#^CONF_DIR=.*#CONF_DIR=\"${tmp}/etc/nftables.d\"#" \
        -e "s#^MAIN_CONF=.*#MAIN_CONF=\"${tmp}/etc/nftables.conf\"#" \
        -e "s#^SYSCTL_CONF=.*#SYSCTL_CONF=\"${tmp}/etc/sysctl.d/99-nft-forward.conf\"#" \
        -e "s#^LOG_FILE=.*#LOG_FILE=\"${tmp}/var/log/nft-forward.log\"#" \
        -e "s#^LOGROTATE_CONF=.*#LOGROTATE_CONF=\"${tmp}/etc/logrotate.d/nft-forward\"#" \
        -e "s#^LOCAL_BIN=.*#LOCAL_BIN=\"${tmp}/nft-forward\"#" \
        "${SCRIPT}" > "${test_script}"
    chmod +x "${test_script}"

    unshare --net bash -s -- "${test_script}" "${tmp}" <<'NS'
set -Eeuo pipefail
SCRIPT=$1
TMP=$2
export PATH="${TMP}/bin:${PATH}"

ip link set lo up
ip link add wan0 type dummy
ip addr add 192.0.2.10/24 dev wan0
ip link set wan0 up
ip route add default via 192.0.2.1 dev wan0 || true

# Add one port with a 1 KiB monthly limit. The blank line accepts auto interface.
printf '3\n12345\n198.51.100.20\n23456\ntest\n1K\n\nY\n12\n' | "${SCRIPT}" >/tmp/nft-forward-runtime-add.out

nft list table ip port_forward | grep -q 'iifname "wan0" tcp dport 12345 dnat to 198.51.100.20:23456'
nft list table inet port_forward_meter | grep -q 'quota monthly_12345'
nft list table inet port_forward_meter | grep -q 'counter upload_12345'
nft list table inet port_forward_meter | grep -q 'counter download_12345'
upload_line=$(nft -a list chain inet port_forward_meter forward_meter | grep -n 'counter name "upload_12345"' | cut -d: -f1)
quota_line=$(nft -a list chain inet port_forward_meter forward_meter | grep -n 'quota name "monthly_12345" drop' | cut -d: -f1)
[[ -n "$upload_line" && -n "$quota_line" && "$upload_line" -lt "$quota_line" ]]

"${SCRIPT}" --traffic >/tmp/nft-forward-runtime-traffic.out
grep -q '12345' /tmp/nft-forward-runtime-traffic.out
grep -q '1.00 KiB' /tmp/nft-forward-runtime-traffic.out
grep -q 'auto:wan0' /tmp/nft-forward-runtime-traffic.out

# Inject known named-object values and verify the display/parser path.
nft delete table inet port_forward_meter
nft -f - <<'NFT'
table inet port_forward_meter {
    counter upload_12345 { packets 2 bytes 400 }
    counter download_12345 { packets 3 bytes 600 }
    quota monthly_12345 { over 1024 bytes used 1000 bytes }
    chain forward_meter {
        type filter hook forward priority -10; policy accept;
        ct status dnat ct original proto-dst 12345 ct direction original counter name "upload_12345"
        ct status dnat ct original proto-dst 12345 ct direction reply counter name "download_12345"
        ct status dnat ct original proto-dst 12345 quota name "monthly_12345" drop
    }
}
NFT
"${SCRIPT}" --traffic >/tmp/nft-forward-runtime-known.out
grep -q '400 B' /tmp/nft-forward-runtime-known.out
grep -q '600 B' /tmp/nft-forward-runtime-known.out
grep -q '1000 B' /tmp/nft-forward-runtime-known.out

# Script reset must zero counters and quotas without rebuilding the table.
"${SCRIPT}" --reset-traffic --quiet
nft -j list counter inet port_forward_meter upload_12345 | python3 -c 'import json,sys; d=json.load(sys.stdin); assert next(x["counter"]["bytes"] for x in d["nftables"] if "counter" in x) == 0'
nft -j list quota inet port_forward_meter monthly_12345 | python3 -c 'import json,sys; d=json.load(sys.stdin); assert next(x["quota"].get("used",0) for x in d["nftables"] if "quota" in x) == 0'

# Idempotent config parse: listing the generated rule must recover limit/interface metadata.
"${SCRIPT}" --traffic >/tmp/nft-forward-runtime-traffic2.out
grep -q '1.00 KiB' /tmp/nft-forward-runtime-traffic2.out
grep -q 'auto:wan0' /tmp/nft-forward-runtime-traffic2.out
NS

    # Validate generated systemd units without touching the host systemd directory.
    mkdir -p "${tmp}/etc/systemd/system"
    cp "${SCRIPT}" "${tmp}/timer-script.sh"
    python3 - "${tmp}/timer-script.sh" "${tmp}" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
tmp = sys.argv[2]
s = path.read_text()
s = s.replace('LOCAL_BIN="/usr/local/bin/nft-forward"', f'LOCAL_BIN="{tmp}/nft-forward"')
s = s.replace('cat > "/etc/systemd/system/${SERVICE_NAME}"', f'cat > "{tmp}/etc/systemd/system/${{SERVICE_NAME}}"')
s = s.replace('cat > "/etc/systemd/system/${TIMER_NAME}"', f'cat > "{tmp}/etc/systemd/system/${{TIMER_NAME}}"')
path.write_text(s)
PY
    PATH="${tmp}/bin:${PATH}" "${tmp}/timer-script.sh" --install-timer >/tmp/nft-forward-timer.out
    grep -q 'OnCalendar=\*-\*-01 00:00:00' "${tmp}/etc/systemd/system/nft-forward-reset.timer"
    grep -q 'Persistent=true' "${tmp}/etc/systemd/system/nft-forward-reset.timer"
    grep -q "ExecStart=${tmp}/nft-forward --reset-traffic --quiet" "${tmp}/etc/systemd/system/nft-forward-reset.service"

    pass "real nftables config, per-port counters/quota, auto interface and reset"
}

test_static_and_cli
test_namespace_runtime
echo "ALL TESTS PASSED"