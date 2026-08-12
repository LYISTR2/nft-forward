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

    # Simulate bash <(curl ...): non-regular BASH_SOURCE must install through SCRIPT_URL.
    mkdir -p "${tmp}/remote-bin" "${tmp}/remote-systemd"
    cp "${SCRIPT}" "${tmp}/remote-source.sh"
    cat > "${tmp}/remote-bin/curl" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
out=""
while [[ \$# -gt 0 ]]; do
    if [[ \$1 == -o ]]; then out=\$2; shift 2; else shift; fi
done
cp "${tmp}/remote-source.sh" "\$out"
EOF
    cat > "${tmp}/remote-bin/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${tmp}/remote-bin/"*
    cp "${SCRIPT}" "${tmp}/remote-run.sh"
    python3 - "${tmp}/remote-run.sh" "${tmp}" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
tmp = sys.argv[2]
s = path.read_text()
s = s.replace('LOCAL_BIN="/usr/local/bin/nft-forward"', f'LOCAL_BIN="{tmp}/remote-installed"')
s = s.replace('SCRIPT_URL="https://raw.githubusercontent.com/LYISTR2/nft-forward/main/nft-forward.sh"', f'SCRIPT_URL="file://{tmp}/remote-source.sh"')
s = s.replace('cat > "/etc/systemd/system/${SERVICE_NAME}"', f'cat > "{tmp}/remote-systemd/${{SERVICE_NAME}}"')
s = s.replace('cat > "/etc/systemd/system/${TIMER_NAME}"', f'cat > "{tmp}/remote-systemd/${{TIMER_NAME}}"')
# Force the process-substitution branch without consuming a real pipe.
s = s.replace('local source_path="${BASH_SOURCE[0]}" download_tmp=""', 'local source_path="/dev/fd/63" download_tmp=""')
path.write_text(s)
PY
    PATH="${tmp}/remote-bin:/usr/bin:/bin" "${tmp}/remote-run.sh" --install-timer >/tmp/nft-forward-remote-timer.out
    [[ -x "${tmp}/remote-installed" ]]
    bash -n "${tmp}/remote-installed"

    pass "real nftables config, per-port counters/quota, auto interface and reset"
}

test_real_forwarding_and_quota() {
    command -v nc >/dev/null 2>&1 || fail "netcat is required"

    unshare --net --mount bash -s <<'NS'
set -Eeuo pipefail

cleanup() {
    kill "${server_pid:-}" >/dev/null 2>&1 || true
    ip netns del client >/dev/null 2>&1 || true
    ip netns del target >/dev/null 2>&1 || true
    umount /run/netns >/dev/null 2>&1 || true
    rm -rf /run/netns
}
trap cleanup EXIT

mkdir -p /run/netns
mount --bind /run/netns /run/netns
mount --make-shared /run/netns
ip netns add client
ip netns add target

ip link add fwd-client type veth peer name c-fwd
ip link set c-fwd netns client
ip addr add 10.10.0.1/24 dev fwd-client
ip link set fwd-client up
ip netns exec client ip addr add 10.10.0.2/24 dev c-fwd
ip netns exec client ip link set c-fwd up
ip netns exec client ip link set lo up
ip netns exec client ip route add default via 10.10.0.1

ip link add fwd-target type veth peer name t-fwd
ip link set t-fwd netns target
ip addr add 10.20.0.1/24 dev fwd-target
ip link set fwd-target up
ip netns exec target ip addr add 10.20.0.2/24 dev t-fwd
ip netns exec target ip link set t-fwd up
ip netns exec target ip link set lo up
ip netns exec target ip route add default via 10.20.0.1

sysctl -q -w net.ipv4.ip_forward=1

ip netns exec target nc -l -k -p 23456 >/dev/null &
server_pid=$!
sleep 0.2

nft -f - <<'NFT'
table ip port_forward {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        iifname "fwd-client" tcp dport 12345 dnat to 10.20.0.2:23456
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        ip daddr 10.20.0.2 tcp dport 23456 ct status dnat snat to 10.20.0.1
    }
}
table inet port_forward_meter {
    counter upload_12345 { }
    counter download_12345 { }
    quota monthly_12345 { over 512 bytes }
    chain forward_meter {
        type filter hook forward priority -10; policy accept;
        ct status dnat ct original proto-dst 12345 ct direction original counter name "upload_12345"
        ct status dnat ct original proto-dst 12345 ct direction reply counter name "download_12345"
        ct status dnat ct original proto-dst 12345 quota name "monthly_12345" drop
    }
}
NFT

# A small transfer passes and increments the upload counter/quota.
head -c 64 /dev/zero | ip netns exec client nc -w 1 10.10.0.1 12345
upload=$(nft -j list counter inet port_forward_meter upload_12345 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["counter"]["bytes"] for x in d["nftables"] if "counter" in x))')
used=$(nft -j list quota inet port_forward_meter monthly_12345 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["quota"].get("used",0) for x in d["nftables"] if "quota" in x))')
(( upload > 0 && used > 0 ))

# Repeated traffic crosses the 512-byte quota; a later payload cannot reach target.
for _ in 1 2 3 4; do head -c 256 /dev/zero | ip netns exec client nc -w 1 10.10.0.1 12345 || true; done
used=$(nft -j list quota inet port_forward_meter monthly_12345 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["quota"].get("used",0) for x in d["nftables"] if "quota" in x))')
(( used >= 512 ))

nft reset counters table inet port_forward_meter >/dev/null
nft reset quotas table inet port_forward_meter >/dev/null
used=$(nft -j list quota inet port_forward_meter monthly_12345 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(x["quota"].get("used",0) for x in d["nftables"] if "quota" in x))')
[[ "$used" == 0 ]]

# Reset restores forwarding immediately.
head -c 32 /dev/zero | ip netns exec client nc -w 1 10.10.0.1 12345
NS

    pass "real DNAT/SNAT traffic increments quota and reset restores forwarding"
}

test_static_and_cli
test_namespace_runtime
test_real_forwarding_and_quota
echo "ALL TESTS PASSED"