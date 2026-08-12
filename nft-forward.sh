#!/usr/bin/env bash
#
# nftables 端口转发管理工具 v2.0
# 交互式管理 DNAT 端口转发、按端口流量统计与月度流量限制
#

set -o pipefail

# ============== 常量定义 ==============
CONF_DIR="/etc/nftables.d"
CONF_FILE="${CONF_DIR}/port-forward.conf"
BACKUP_DIR="${CONF_DIR}/backups"
MAIN_CONF="/etc/nftables.conf"
SYSCTL_CONF="/etc/sysctl.d/99-nft-forward.conf"
LOG_FILE="/var/log/nft-forward.log"
LOGROTATE_CONF="/etc/logrotate.d/nft-forward"
TABLE_NAME="port_forward"
TIMER_NAME="nft-forward-reset.timer"
SERVICE_NAME="nft-forward-reset.service"
LOCAL_BIN="/usr/local/bin/nft-forward"
SCRIPT_URL="https://raw.githubusercontent.com/LYISTR2/nft-forward/main/nft-forward.sh"

# 规则格式: 本机端口|目标IP|目标端口|备注|月流量限制字节(0=不限)|入站网卡(auto=自动)
declare -a RULES=()
SELECTED_INDEX=-1
SELECTED_RULE=""

# ============== 日志与输出 ==============
log_action() {
    local msg="$1"
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}
info() { printf '\033[32m[信息]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$1"; }
err()  { printf '\033[31m[错误]\033[0m %s\n' "$1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "此脚本需要 root 权限运行，请使用 sudo 或 root 用户执行。"
        exit 1
    fi
}

# ============== 输入验证与格式化 ==============
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    [[ ! "$port" =~ ^0[0-9] ]] || return 1
    (( port >= 1 && port <= 65535 ))
}

validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    [[ ! "$ip" =~ (^|\.)0[0-9] ]] || return 1
    local IFS='.' octets octet
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( octet <= 255 )) || return 1
    done
}

validate_iface() {
    local iface="$1"
    [[ "$iface" == "auto" ]] && return 0
    [[ "$iface" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || return 1
    [[ -d "/sys/class/net/${iface}" ]] || return 1
}

sanitize_note() {
    local note="${1:-}"
    note="${note//$'\r'/ }"
    note="${note//$'\n'/ }"
    note="${note//|/ }"
    printf "%s" "$note"
}

parse_size_bytes() {
    local raw="${1:-}" number unit power=0
    raw="${raw//[[:space:]]/}"
    raw="${raw^^}"
    [[ -n "$raw" ]] || return 1
    [[ "$raw" =~ ^(0|NONE|UNLIMITED)$ ]] && { echo 0; return; }
    [[ "$raw" =~ ^([0-9]+)(B|K|KB|KIB|M|MB|MIB|G|GB|GIB|T|TB|TIB)?$ ]] || return 1
    number="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]:-B}"
    (( number > 0 )) || return 1
    case "$unit" in
        K|KB|KIB) power=1 ;;
        M|MB|MIB) power=2 ;;
        G|GB|GIB) power=3 ;;
        T|TB|TIB) power=4 ;;
    esac
    local multiplier=$((1024 ** power))
    (( number <= 9223372036854775807 / multiplier )) || return 1
    echo $((number * multiplier))
}

format_bytes() {
    local bytes="${1:-0}"
    [[ "$bytes" =~ ^[0-9]+$ ]] || bytes=0
    awk -v b="$bytes" 'BEGIN {
        split("B KiB MiB GiB TiB PiB", u, " "); i=1;
        while (b >= 1024 && i < 6) { b /= 1024; i++ }
        if (i == 1) printf "%.0f %s", b, u[i]; else printf "%.2f %s", b, u[i]
    }'
}

# ============== 网卡与本机 IP ==============
get_local_ip() {
    local ip=""
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}') || true
    [[ -n "$ip" ]] && { echo "$ip"; return; }
    ip=$(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}') || true
    [[ -n "$ip" ]] && { echo "$ip"; return; }
    hostname -I 2>/dev/null | awk '{print $1}' || true
}

get_default_iface() {
    local iface
    iface=$(ip -4 route show default 2>/dev/null | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}') || true
    [[ -n "$iface" ]] && { echo "$iface"; return; }
    iface=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}') || true
    [[ -n "$iface" ]] && echo "$iface"
}

show_iface_traffic() {
    local iface rx tx
    iface=$(get_default_iface)
    if [[ -z "$iface" ]]; then
        warn "无法自动识别默认出口网卡。"
        return
    fi
    if [[ -r "/sys/class/net/${iface}/statistics/rx_bytes" ]]; then
        read -r rx < "/sys/class/net/${iface}/statistics/rx_bytes"
    else
        rx=0
    fi
    if [[ -r "/sys/class/net/${iface}/statistics/tx_bytes" ]]; then
        read -r tx < "/sys/class/net/${iface}/statistics/tx_bytes"
    else
        tx=0
    fi
    info "自动识别默认网卡: ${iface}"
    printf "  接收(RX): %s\n" "$(format_bytes "$rx")"
    printf "  发送(TX): %s\n" "$(format_bytes "$tx")"
    printf "  合计:     %s\n" "$(format_bytes "$((rx + tx))")"
    warn "网卡统计包含整台服务器全部流量；端口额度以 nftables 的每端口计数为准。"
}

# ============== 发行版与防火墙 ==============
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then echo apt
    elif command -v dnf &>/dev/null; then echo dnf
    elif command -v yum &>/dev/null; then echo yum
    elif command -v pacman &>/dev/null; then echo pacman
    else echo unknown; fi
}

has_iptables() {
    command -v iptables &>/dev/null && iptables -S &>/dev/null
}

try_persist_iptables() {
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 && return 0
    fi
    if command -v iptables-save &>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null && return 0
        elif [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null && return 0
        fi
    fi
    if command -v service &>/dev/null; then
        service iptables save >/dev/null 2>&1 && return 0
    fi
    return 1
}

dest_still_used() {
    local check_ip="$1" check_dport="$2" exclude_lport="$3"
    local rule lport dip dport note limit iface
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        [[ "$lport" == "$exclude_lport" ]] && continue
        [[ "$dip" == "$check_ip" && "$dport" == "$check_dport" ]] && return 0
    done
    return 1
}

firewall_open_port() {
    local lport="$1" dest_ip="$2" dport="$3"
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --add-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --add-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "已在 firewalld 中放行端口 ${lport} (tcp+udp)。"
        log_action "firewalld 放行端口 ${lport}"
        return
    fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw active; then
        ufw allow "${lport}/tcp" >/dev/null 2>&1 || true
        ufw allow "${lport}/udp" >/dev/null 2>&1 || true
        ufw route allow proto tcp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        ufw route allow proto udp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        info "已在 UFW 中放行端口 ${lport} 及转发到 ${dest_ip}:${dport} (tcp+udp)。"
        log_action "UFW 放行端口 ${lport} 转发到 ${dest_ip}:${dport}"
        return
    fi
    if has_iptables; then
        iptables -C INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || iptables -I FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || iptables -I FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        info "已在 iptables 中放行: INPUT ${lport}, FORWARD → ${dest_ip}:${dport} (tcp+udp)。"
        log_action "iptables 放行 INPUT:${lport} FORWARD:${dest_ip}:${dport}"
        try_persist_iptables || warn "iptables 规则已生效但未能自动持久化，重启后可能丢失。"
    fi
}

firewall_close_port() {
    local lport="$1" dest_ip="$2" dport="$3" force="${4:-}"
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --remove-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --remove-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        return
    fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw active; then
        yes | ufw delete allow "${lport}/tcp" >/dev/null 2>&1 || true
        yes | ufw delete allow "${lport}/udp" >/dev/null 2>&1 || true
        if [[ "$force" == force ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            yes | ufw route delete allow proto tcp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
            yes | ufw route delete allow proto udp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        fi
        return
    fi
    if has_iptables; then
        iptables -D INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        if [[ "$force" == force ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            iptables -D FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        fi
        try_persist_iptables || true
    fi
}

check_port_conflict() {
    local port="$1" conflict=""
    ss -tlnp 2>/dev/null | grep -qE ":${port}\b" && conflict=TCP
    if ss -ulnp 2>/dev/null | grep -qE ":${port}\b"; then
        [[ -n "$conflict" ]] && conflict="TCP+UDP" || conflict=UDP
    fi
    if [[ -n "$conflict" ]]; then
        warn "本机端口 ${port} 已被其他服务占用（${conflict}）。"
        read -rp "是否仍要继续添加转发规则？[y/N]: " ans || return 1
        [[ "$ans" =~ ^[Yy]$ ]] || return 1
    fi
}

load_rules_or_info() {
    local message="${1:-当前没有端口转发规则。}"
    load_rules
    (( ${#RULES[@]} > 0 )) || { info "$message"; return 1; }
}

select_rule() {
    local prompt="$1" choice
    do_list_table
    read -rp "$prompt" choice || return 1
    [[ "$choice" == 0 || -z "$choice" ]] && return 1
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#RULES[@]} )); then
        err "无效序号。"
        return 1
    fi
    SELECTED_INDEX=$((choice - 1))
    SELECTED_RULE="${RULES[SELECTED_INDEX]}"
}

limit_text() {
    if [[ "${1:-0}" == 0 ]]; then
        echo 不限
    else
        format_bytes "$1"
    fi
}

# ============== 配置读写 ==============
get_conf_local_ip() {
    [[ -f "${CONF_FILE}" ]] || return
    local line
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*define[[:space:]]+LOCAL_IP[[:space:]]*=[[:space:]]*([0-9.]+) ]]; then
            printf "%s" "${BASH_REMATCH[1]}"
            return
        fi
    done < "${CONF_FILE}"
}

load_rules() {
    RULES=()
    [[ -f "${CONF_FILE}" ]] || return
    local pending_note="" pending_limit=0 pending_iface=auto line
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*备注:[[:space:]]*(.*)$ ]]; then
            pending_note=$(sanitize_note "${BASH_REMATCH[1]}")
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*月流量限制字节:[[:space:]]*([0-9]+) ]]; then
            pending_limit="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*入站网卡:[[:space:]]*([A-Za-z0-9_.:-]+) ]]; then
            pending_iface="${BASH_REMATCH[1]}"
            continue
        fi
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ tcp[[:space:]]+dport[[:space:]]+([0-9]+)[[:space:]]+dnat[[:space:]]+to[[:space:]]+([0-9.]+):([0-9]+) ]]; then
            RULES+=("${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|${BASH_REMATCH[3]}|${pending_note}|${pending_limit}|${pending_iface}")
            pending_note=""
            pending_limit=0
            pending_iface=auto
        fi
    done < "${CONF_FILE}"
}

backup_conf() {
    [[ -f "${CONF_FILE}" ]] || return
    mkdir -p "${BACKUP_DIR}" 2>/dev/null || true
    cp "${CONF_FILE}" "${BACKUP_DIR}/port-forward.conf.$(date '+%Y%m%d_%H%M%S')" 2>/dev/null || true
}

write_conf_file() {
    local local_ip default_iface
    local_ip=$(get_local_ip)
    [[ -n "$local_ip" ]] || local_ip=$(get_conf_local_ip)
    [[ -n "$local_ip" ]] || { err "无法获取本机 IP 地址，请检查网络配置。"; return 1; }
    default_iface=$(get_default_iface)

    mkdir -p "${CONF_DIR}" "${BACKUP_DIR}" 2>/dev/null || return 1
    local tmp_file="${CONF_FILE}.tmp.$$"
    cat > "${tmp_file}" <<EOF
#!/usr/sbin/nft -f

# 由 nft-forward 管理；规则元数据保存在注释中。
define LOCAL_IP = ${local_ip}

# --- NAT 表 ---
table ip ${TABLE_NAME} {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
EOF

    local rule lport dip dport note limit iface effective_iface iface_expr proto direction address_field port_field counter_name
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        limit="${limit:-0}"
        iface="${iface:-auto}"
        effective_iface="$iface"
        [[ "$effective_iface" == auto ]] && effective_iface="$default_iface"
        iface_expr=""
        [[ -n "$effective_iface" ]] && iface_expr="iifname \"${effective_iface}\" "
        cat >> "${tmp_file}" <<EOF

        # 转发: 本机:${lport} -> ${dip}:${dport}
        # 月流量限制字节: ${limit}
        # 入站网卡: ${iface}
EOF
        [[ -n "$note" ]] && echo "        # 备注: ${note}" >> "${tmp_file}"
        cat >> "${tmp_file}" <<EOF
        ${iface_expr}tcp dport ${lport} dnat to ${dip}:${dport}
        ${iface_expr}udp dport ${lport} dnat to ${dip}:${dport}
EOF
    done

    cat >> "${tmp_file}" <<EOF
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
EOF
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        for proto in tcp udp; do
            echo "        ip daddr ${dip} ${proto} dport ${dport} ct status dnat snat to \$LOCAL_IP" >> "${tmp_file}"
        done
    done
    cat >> "${tmp_file}" <<EOF
    }
}

# --- 每端口流量计数与限额表 ---
table inet ${TABLE_NAME}_meter {
EOF
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        limit="${limit:-0}"
        cat >> "${tmp_file}" <<EOF
    counter upload_${lport} { }
    counter download_${lport} { }
EOF
        if (( limit > 0 )); then
            cat >> "${tmp_file}" <<EOF
    quota monthly_${lport} { over ${limit} bytes }
EOF
        fi
    done

    cat >> "${tmp_file}" <<EOF

    chain forward_meter {
        type filter hook forward priority -10; policy accept;
EOF
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        limit="${limit:-0}"
        for direction in original reply; do
            if [[ "$direction" == original ]]; then
                address_field=daddr; port_field=dport; counter_name="upload_${lport}"
            else
                address_field=saddr; port_field=sport; counter_name="download_${lport}"
            fi
            for proto in tcp udp; do
                echo "        ct status dnat ct direction ${direction} meta l4proto ${proto} ip ${address_field} ${dip} ${proto} ${port_field} ${dport} counter name \"${counter_name}\"" >> "${tmp_file}"
            done
        done
        if (( limit > 0 )); then
            for direction in original reply; do
                if [[ "$direction" == original ]]; then address_field=daddr; port_field=dport; else address_field=saddr; port_field=sport; fi
                for proto in tcp udp; do
                    echo "        ct status dnat meta l4proto ${proto} ip ${address_field} ${dip} ${proto} ${port_field} ${dport} quota name \"monthly_${lport}\" drop" >> "${tmp_file}"
                done
            done
        fi
    done
    cat >> "${tmp_file}" <<EOF
    }
}
EOF

    if ! nft -c -f "${tmp_file}"; then
        err "新配置语法检查失败，已保留原配置。"
        rm -f "${tmp_file}"
        return 1
    fi
    mv -f "${tmp_file}" "${CONF_FILE}" || return 1
}

init_conf() {
    mkdir -p "${CONF_DIR}" "${BACKUP_DIR}" "$(dirname "${LOGROTATE_CONF}")" 2>/dev/null || return 1
    touch "${LOG_FILE}" 2>/dev/null || true
    if [[ ! -f "${LOGROTATE_CONF}" ]]; then
        cat > "${LOGROTATE_CONF}" <<'LOGROTATE'
/var/log/nft-forward.log {
    monthly
    rotate 6
    compress
    missingok
    notifempty
}
LOGROTATE
    fi
    if [[ ! -f "${MAIN_CONF}" ]]; then
        cat > "${MAIN_CONF}" <<'NFTCONF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.conf"
NFTCONF
        info "已创建 ${MAIN_CONF}。"
    elif ! grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
        echo 'include "/etc/nftables.d/*.conf"' >> "${MAIN_CONF}"
        info "已在 ${MAIN_CONF} 中添加 include 指令。"
    fi
    [[ -f "${CONF_FILE}" ]] || write_conf_file
}

reload_rules() {
    if ! nft -c -f "${CONF_FILE}"; then
        err "配置语法检查失败，未修改当前运行规则。"
        return 1
    fi
    nft delete table ip "${TABLE_NAME}" 2>/dev/null || true
    nft delete table inet "${TABLE_NAME}_meter" 2>/dev/null || true
    if ! nft -f "${CONF_FILE}"; then
        err "加载配置文件失败，请检查 ${CONF_FILE}"
        return 1
    fi
}

# ============== 内核与 systemd ==============
enable_ip_forward() {
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != 1 ]]; then
        if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
            info "已开启 IPv4 转发。"
        else
            warn "无法开启 IPv4 转发。"
        fi
    fi
    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    if grep -qE '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "${SYSCTL_CONF}" 2>/dev/null; then
        sed -i -E 's|^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*|net.ipv4.ip_forward=1|' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo 'net.ipv4.ip_forward=1' >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi
}

set_sysctl_conf() {
    local key="$1" value="$2" escaped=${1//./\\.}
    if grep -qE "^[[:space:]]*${escaped}[[:space:]]*=" "${SYSCTL_CONF}" 2>/dev/null; then
        sed -i -E "s|^[[:space:]]*${escaped}[[:space:]]*=.*|${key}=${value}|" "${SYSCTL_CONF}"
    else
        echo "${key}=${value}" >> "${SYSCTL_CONF}"
    fi
}

enable_bbr_fq() {
    modprobe tcp_bbr 2>/dev/null || true
    grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || { warn "内核不支持 BBR，已跳过。"; return; }
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    set_sysctl_conf net.core.default_qdisc fq
    set_sysctl_conf net.ipv4.tcp_congestion_control bbr
    info "已尝试开启并持久化 BBR + fq。"
}

download_script() {
    local tmp
    tmp=$(mktemp /tmp/nft-forward-install.XXXXXX) || return 1
    if command -v curl &>/dev/null && curl -fsSL "$SCRIPT_URL" -o "$tmp"; then
        echo "$tmp"
        return
    fi
    if command -v wget &>/dev/null && wget -qO "$tmp" "$SCRIPT_URL"; then
        echo "$tmp"
        return
    fi
    rm -f "$tmp"
    return 1
}

install_reset_timer() {
    command -v systemctl &>/dev/null || { warn "未找到 systemctl，无法安装月度重置定时器。"; return 1; }
    local source_path="${BASH_SOURCE[0]}" download_tmp=""
    if [[ -f "$source_path" && -r "$source_path" && "$source_path" != /dev/fd/* && "$source_path" != /proc/*/fd/* ]]; then
        install -m 0755 "$source_path" "${LOCAL_BIN}" 2>/dev/null || true
    else
        download_tmp=$(download_script) || true
        if [[ -n "$download_tmp" ]] && bash -n "$download_tmp"; then
            install -m 0755 "$download_tmp" "${LOCAL_BIN}" 2>/dev/null || true
        fi
        [[ -n "$download_tmp" ]] && rm -f "$download_tmp"
    fi
    [[ -x "${LOCAL_BIN}" ]] || { warn "无法安装 ${LOCAL_BIN}，月度重置定时器未启用。"; return 1; }
    cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=Reset nft-forward monthly traffic counters and quotas
After=nftables.service

[Service]
Type=oneshot
ExecStart=${LOCAL_BIN} --reset-traffic --quiet
EOF
    cat > "/etc/systemd/system/${TIMER_NAME}" <<EOF
[Unit]
Description=Reset nft-forward traffic on the first day of each month

[Timer]
OnCalendar=*-*-01 00:00:00
Persistent=true
RandomizedDelaySec=30s
Unit=${SERVICE_NAME}

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl enable --now "${TIMER_NAME}" >/dev/null 2>&1; then
        info "已启用月度流量重置: 每月 1 日 00:00。"
        return 0
    fi
    warn "月度重置 timer 启用失败，请手动执行: systemctl enable --now ${TIMER_NAME}"
    return 1
}

# ============== 流量统计 ==============
get_nft_object_field() {
    local kind="$1" name="$2" field="$3"
    nft -j list "$kind" inet "${TABLE_NAME}_meter" "$name" 2>/dev/null | python3 -c '
import json,sys
kind,name,field=sys.argv[1:]
try: data=json.load(sys.stdin)
except Exception: print(0); raise SystemExit
for item in data.get("nftables",[]):
    obj=item.get(kind)
    if obj and obj.get("name")==name:
        print(obj.get(field,0)); raise SystemExit
print(0)
' "$kind" "$name" "$field" 2>/dev/null || echo 0
}

quota_used_for_port() {
    local lport="$1" used
    used=$(get_nft_object_field quota "monthly_${lport}" used)
    if [[ "$used" =~ ^[0-9]+$ ]]; then
        echo "$used"
    else
        echo 0
    fi
}

show_traffic() {
    load_rules
    echo ""
    echo "========================================"
    echo "        每端口月度流量统计"
    echo "========================================"
    if [[ ${#RULES[@]} -eq 0 ]]; then
        info "当前没有端口转发规则。"
        show_iface_traffic
        return
    fi
    printf "%-8s %-18s %-14s %-14s %-14s %-14s %-8s %-12s\n" "端口" "目标" "上传" "下载" "合计" "月限额" "状态" "入站网卡"
    echo "────────────────────────────────────────────────────────────────────────────────────────────────"
    local rule lport dip dport note limit iface upload download total quota_used status display_iface
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        limit="${limit:-0}"
        iface="${iface:-auto}"
        upload=$(get_nft_object_field counter "upload_${lport}" bytes)
        download=$(get_nft_object_field counter "download_${lport}" bytes)
        total=$((upload + download))
        quota_used=0
        status=正常
        if (( limit > 0 )); then
            quota_used=$(quota_used_for_port "$lport")
            (( quota_used >= limit )) && status=已停
        fi
        display_iface="$iface"
        [[ "$display_iface" == auto ]] && display_iface="auto:$(get_default_iface)"
        local limit_text
        limit_text=$(limit_text "$limit")
        printf "%-8s %-18s %-14s %-14s %-14s %-14s %-8s %-12s\n" \
            "$lport" "${dip}:${dport}" "$(format_bytes "$upload")" "$(format_bytes "$download")" \
            "$(format_bytes "$total")" "$limit_text" "$status" "$display_iface"
    done
    echo ""
    show_iface_traffic
    echo ""
    info "计费口径: 转发连接的双向 IP 流量总和；超限后新旧转发包均在 forward 链被丢弃。"
}

reset_traffic() {
    local quiet="${1:-}"
    if ! nft list table inet "${TABLE_NAME}_meter" &>/dev/null; then
        [[ "$quiet" == quiet ]] || warn "流量统计表尚未加载。"
        return 0
    fi
    nft reset counters table inet "${TABLE_NAME}_meter" >/dev/null 2>&1 || true
    nft reset quotas table inet "${TABLE_NAME}_meter" >/dev/null 2>&1 || true
    log_action "重置所有端口月度流量计数与限额"
    [[ "$quiet" == quiet ]] || info "所有端口流量统计与月度限额已重置。"
}

configure_limit() {
    load_rules_or_info || return
    select_rule "请输入要设置流量限制的序号 (0 取消): " || return
    local raw bytes lport dip dport note limit iface
    read -rp "请输入每月流量限制（如 500G、2T；0 表示不限）: " raw || return
    bytes=$(parse_size_bytes "$raw") || { err "流量格式无效。"; return; }
    IFS='|' read -r lport dip dport note limit iface <<< "$SELECTED_RULE"
    backup_conf
    RULES[SELECTED_INDEX]="${lport}|${dip}|${dport}|${note}|${bytes}|${iface:-auto}"
    if write_conf_file && reload_rules; then
        install_reset_timer || true
        info "端口 ${lport} 月流量限制已设置为: $(limit_text "$bytes")"
        warn "重新生成规则会从 0 开始统计该端口本月流量。"
        log_action "设置流量限制: 端口 ${lport} 限额 ${bytes} 字节"
    fi
}

configure_iface() {
    load_rules_or_info || return
    select_rule "请输入要设置入站网卡的序号 (0 取消): " || return
    local iface lport dip dport note limit _old_iface
    read -rp "输入网卡名（auto 自动识别，当前默认: $(get_default_iface)）: " iface || return
    iface="${iface:-auto}"
    validate_iface "$iface" || { err "网卡不存在或名称无效。"; return; }
    IFS='|' read -r lport dip dport note limit _old_iface <<< "$SELECTED_RULE"
    backup_conf
    RULES[SELECTED_INDEX]="${lport}|${dip}|${dport}|${note}|${limit:-0}|${iface}"
    if write_conf_file && reload_rules; then
        info "端口 ${lport} 入站网卡已设置为 ${iface}。"
        log_action "设置入站网卡: 端口 ${lport} 网卡 ${iface}"
    fi
}

# ============== 安装、诊断与规则管理 ==============
check_firewall_status() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then info "检测到 firewalld。"
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw active; then info "检测到 UFW。"
    elif has_iptables; then info "检测到 iptables 规则集。"; fi
}

do_diagnose() {
    echo ""
    echo "========================================"
    echo "           诊断 / 自检"
    echo "========================================"
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == 1 ]]; then info "IPv4 转发: 已开启"; else err "IPv4 转发: 未开启"; fi
    if command -v nft &>/dev/null; then info "nftables: 已安装 ($(nft --version 2>/dev/null))"; else err "nftables: 未安装"; fi
    if nft list table ip "${TABLE_NAME}" &>/dev/null; then info "NAT 转发表: 已加载"; else warn "NAT 转发表: 未加载"; fi
    if nft list table inet "${TABLE_NAME}_meter" &>/dev/null; then info "流量统计表: 已加载"; else warn "流量统计表: 未加载"; fi
    local iface
    iface=$(get_default_iface)
    if [[ -n "$iface" ]]; then info "自动识别默认网卡: ${iface}"; else warn "无法识别默认网卡"; fi
    if systemctl is-enabled --quiet "${TIMER_NAME}" 2>/dev/null; then info "月度重置 timer: 已启用"; else warn "月度重置 timer: 未启用"; fi
    if [[ -f "${CONF_FILE}" ]] && nft -c -f "${CONF_FILE}" >/dev/null 2>&1; then info "配置语法: 正常"; else warn "配置文件不存在或语法异常"; fi
    show_iface_traffic
}

do_install() {
    echo ""
    if command -v nft &>/dev/null; then
        info "nftables 已安装。"
        warn "安装将清空所有已有 nftables 配置，由本脚本统一接管。"
        read -rp "是否继续？[y/N]: " confirm || return
        [[ "$confirm" =~ ^[Yy]$ ]] || { info "已取消。"; return; }
        local ts f
        ts=$(date '+%Y%m%d_%H%M%S')
        if [[ -f "${MAIN_CONF}" ]]; then mv "${MAIN_CONF}" "${MAIN_CONF}.bak.${ts}" 2>/dev/null || true; fi
        if [[ -d "${CONF_DIR}" ]]; then
            for f in "${CONF_DIR}"/*.conf; do
                if [[ -f "$f" ]]; then mv "$f" "${f}.bak.${ts}" 2>/dev/null || true; fi
            done
        fi
        nft flush ruleset 2>/dev/null || true
    else
        info "未检测到 nftables，准备安装..."
        case "$(detect_pkg_manager)" in
            apt) apt-get update -y && apt-get install -y nftables python3 ;;
            dnf) dnf install -y nftables python3 ;;
            yum) yum install -y nftables python3 ;;
            pacman) pacman -Sy --noconfirm nftables python ;;
            *) err "无法识别包管理器，请手动安装 nftables 与 python3。"; return ;;
        esac
        command -v nft &>/dev/null || { err "nftables 安装失败。"; return; }
    fi
    enable_ip_forward
    enable_bbr_fq
    check_firewall_status
    init_conf || { err "配置初始化失败。"; return; }
    nft -f "${MAIN_CONF}" || { err "加载 ${MAIN_CONF} 失败。"; return; }
    systemctl enable --now nftables >/dev/null 2>&1 || warn "nftables 服务启用失败。"
    install_reset_timer || true
    info "安装与初始化完成。"
}

do_list_table() {
    local idx=1 rule lport dip dport note limit iface limit_text
    printf "\n%-6s %-10s %-22s %-16s %-12s %s\n" "序号" "本机端口" "目标地址" "月流量限制" "入站网卡" "备注"
    echo "────────────────────────────────────────────────────────────────────────────────────────"
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        limit="${limit:-0}"
        iface="${iface:-auto}"
        limit_text=$(limit_text "$limit")
        printf "%-6s %-10s %-22s %-16s %-12s %s\n" "$idx" "$lport" "${dip}:${dport}" "$limit_text" "$iface" "${note:--}"
        ((idx++))
    done
}

do_list() {
    echo ""
    load_rules_or_info || return
    do_list_table
}

edit_rule_note() {
    load_rules_or_info || return
    select_rule "请输入要修改备注的序号 (0 取消): " || return
    local lport dip dport _old_note limit iface note
    IFS='|' read -r lport dip dport _old_note limit iface <<< "$SELECTED_RULE"
    read -rp "请输入新备注（留空清除）: " note || return
    note=$(sanitize_note "$note")
    backup_conf
    RULES[SELECTED_INDEX]="${lport}|${dip}|${dport}|${note}|${limit:-0}|${iface:-auto}"
    write_conf_file && reload_rules && info "备注已保存。"
}

do_add() {
    command -v nft &>/dev/null || { err "nftables 未安装，请先安装。"; return; }
    init_conf || return
    enable_ip_forward
    load_rules
    local lport dip dport note confirm raw_limit limit iface rule rp
    while true; do read -rp "请输入本机监听端口 (1-65535): " lport || return; validate_port "$lport" && break; err "端口无效。"; done
    for rule in "${RULES[@]}"; do IFS='|' read -r rp _ <<< "$rule"; [[ "$rp" == "$lport" ]] && { err "端口 ${lport} 已存在规则。"; return; }; done
    check_port_conflict "$lport" || return
    while true; do read -rp "请输入目标 IP 地址: " dip || return; validate_ip "$dip" && break; err "IP 地址格式无效。"; done
    while true; do read -rp "请输入目标端口 [默认 ${lport}]: " dport || return; dport="${dport:-$lport}"; validate_port "$dport" && break; err "端口无效。"; done
    read -rp "请输入备注（可留空）: " note || return
    note=$(sanitize_note "$note")
    while true; do
        read -rp "请输入每月流量限制 [默认不限；如 500G、2T、0]: " raw_limit || return
        raw_limit="${raw_limit:-0}"
        limit=$(parse_size_bytes "$raw_limit") && break
        err "流量格式无效。"
    done
    iface=$(get_default_iface)
    if [[ -n "$iface" ]]; then info "自动识别入站网卡: ${iface}"; else warn "未识别到默认网卡，将匹配所有网卡。"; fi
    read -rp "入站网卡 [默认 auto；可输入具体网卡名]: " iface || return
    iface="${iface:-auto}"
    validate_iface "$iface" || { err "网卡不存在或名称无效。"; return; }
    echo "本机:${lport} (tcp+udp) → ${dip}:${dport}，月限额: $(limit_text "$limit")，网卡: ${iface}"
    read -rp "确认添加？[Y/n]: " confirm || return
    [[ "$confirm" =~ ^[Nn]$ ]] && return
    backup_conf
    RULES+=("${lport}|${dip}|${dport}|${note}|${limit}|${iface}")
    if write_conf_file && reload_rules; then
        firewall_open_port "$lport" "$dip" "$dport"
        install_reset_timer || true
        info "转发规则添加成功。"
        log_action "新增转发: ${lport} -> ${dip}:${dport} 限额:${limit} 网卡:${iface}"
    fi
}

do_delete() {
    command -v nft &>/dev/null || { err "nftables 未安装。"; return; }
    load_rules_or_info "当前没有规则。" || return
    select_rule "请输入要删除的序号 (0 取消): " || return
    local confirm lport dip dport note limit iface
    IFS='|' read -r lport dip dport note limit iface <<< "$SELECTED_RULE"
    read -rp "确认删除端口 ${lport}？[Y/n]: " confirm || return
    [[ "$confirm" =~ ^[Nn]$ ]] && return
    backup_conf
    unset 'RULES[SELECTED_INDEX]'
    RULES=("${RULES[@]}")
    if write_conf_file && reload_rules; then
        firewall_close_port "$lport" "$dip" "$dport"
        info "规则已删除。"
    fi
}

do_clear_all() {
    load_rules_or_info "当前没有规则。" || return
    warn "即将清空全部 ${#RULES[@]} 条规则。"
    read -rp "确认清空？[y/N]: " confirm || return
    [[ "$confirm" =~ ^[Yy]$ ]] || return
    local rule lport dip dport note limit iface
    backup_conf
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note limit iface <<< "$rule"
        firewall_close_port "$lport" "$dip" "$dport" force
    done
    RULES=()
    write_conf_file && reload_rules && info "所有规则已清空。"
}

# ============== 菜单与 CLI ==============
main_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo " nftables 端口转发管理工具 v2.0"
        echo "========================================"
        echo "  1) 安装 / 初始化 nftables"
        echo "  2) 查看端口转发规则"
        echo "  3) 新增端口转发"
        echo "  4) 删除端口转发"
        echo "  5) 清空所有转发"
        echo "  6) 查看流量统计"
        echo "  7) 设置端口月流量限制"
        echo "  8) 设置端口入站网卡"
        echo "  9) 手动重置本月流量"
        echo " 10) 修改规则备注"
        echo " 11) 诊断 / 自检"
        echo " 12) 退出"
        echo "========================================"
        local choice
        if ! read -rp "请选择操作 [1-12]: " choice; then
            echo ""
            info "输入结束，退出。"
            exit 0
        fi
        case "$choice" in
            1) do_install ;;
            2) do_list ;;
            3) do_add ;;
            4) do_delete ;;
            5) do_clear_all ;;
            6) show_traffic ;;
            7) configure_limit ;;
            8) configure_iface ;;
            9) reset_traffic ;;
            10) edit_rule_note ;;
            11) do_diagnose ;;
            12) info "再见！"; exit 0 ;;
            *) err "无效选择，请输入 1-12。" ;;
        esac
    done
}

usage() {
    cat <<EOF
用法: nft-forward [命令]

  --traffic          显示每端口流量和默认网卡流量
  --reset-traffic    重置所有端口计数与月度限额
  --install-timer    安装/修复每月 1 日自动重置 timer
  --diagnose         运行诊断
  --help             显示帮助

无参数时进入交互式菜单。
EOF
}

check_root
case "${1:-}" in
    --traffic) show_traffic ;;
    --reset-traffic)
        if [[ "${2:-}" == --quiet ]]; then reset_traffic quiet; else reset_traffic; fi
        ;;
    --install-timer) install_reset_timer ;;
    --diagnose) do_diagnose ;;
    --help|-h) usage ;;
    "") main_menu ;;
    *) err "未知参数: $1"; usage; exit 2 ;;
esac
