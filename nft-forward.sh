#!/usr/bin/env bash
#
# nftables 端口转发管理工具 v1.2
# 交互式管理 DNAT 端口转发规则
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

# ============== 日志函数 ==============
log_action() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

# ============== 输出辅助 ==============
info()    { printf '\033[32m[信息]\033[0m %s\n' "$1"; }
warn()    { printf '\033[33m[警告]\033[0m %s\n' "$1"; }
err()     { printf '\033[31m[错误]\033[0m %s\n' "$1"; }

# ============== root 权限检查 ==============
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "此脚本需要 root 权限运行，请使用 sudo 或 root 用户执行。"
        exit 1
    fi
}

# ============== 输入验证 ==============
validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" =~ ^0[0-9] ]]; then
        return 1
    fi
    if (( port < 1 || port > 65535 )); then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    if [[ "$ip" =~ (^|\.)0[0-9] ]]; then
        return 1
    fi
    local IFS='.'
    local octets
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet > 255 )); then
            return 1
        fi
    done
    return 0
}

# ============== 自动获取本机 IP ==============
get_local_ip() {
    local ip
    ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1) || true
    if [[ -n "$ip" ]]; then echo "$ip"; return; fi
    ip=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1) || true
    if [[ -n "$ip" ]]; then echo "$ip"; return; fi
    hostname -I 2>/dev/null | awk '{print $1}' || true
}

# ============== 发行版检测 ==============
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then echo "apt"
    elif command -v dnf &>/dev/null; then echo "dnf"
    elif command -v yum &>/dev/null; then echo "yum"
    elif command -v pacman &>/dev/null; then echo "pacman"
    else echo "unknown"; fi
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

# ============== 规则数组 ==============
declare -a RULES=()

sanitize_note() {
    local note="${1:-}"
    note="${note//$'\r'/ }"
    note="${note//$'\n'/ }"
    note="${note//|/ }"
    printf "%s" "$note"
}

dest_still_used() {
    local check_ip="$1" check_dport="$2" exclude_lport="$3"
    local rule lport dip dport note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        [[ "$lport" == "$exclude_lport" ]] && continue
        if [[ "$dip" == "$check_ip" && "$dport" == "$check_dport" ]]; then
            return 0
        fi
    done
    return 1
}

# ============== firewalld / iptables 端口放行 ==============
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

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
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
        if ! try_persist_iptables; then
            warn "iptables 规则已生效但未能自动持久化，重启后可能丢失。"
            warn "如需持久化请安装 iptables-persistent / netfilter-persistent。"
        fi
    fi
}

firewall_close_port() {
    local lport="$1" dest_ip="$2" dport="$3" force="${4:-}"

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --remove-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --remove-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "已从 firewalld 中移除端口 ${lport} 的放行规则。"
        log_action "firewalld 移除端口 ${lport}"
        return
    fi

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        yes | ufw delete allow "${lport}/tcp" >/dev/null 2>&1 || true
        yes | ufw delete allow "${lport}/udp" >/dev/null 2>&1 || true
        if [[ "$force" == "force" ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            yes | ufw route delete allow proto tcp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
            yes | ufw route delete allow proto udp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        fi
        info "已从 UFW 中移除端口 ${lport} 的放行规则。"
        log_action "UFW 移除端口 ${lport}"
        return
    fi

    if has_iptables; then
        iptables -D INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        if [[ "$force" == "force" ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            iptables -D FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        fi
        info "已从 iptables 中移除: INPUT ${lport}, FORWARD → ${dest_ip}:${dport}。"
        log_action "iptables 移除 INPUT:${lport} FORWARD:${dest_ip}:${dport}"
        try_persist_iptables || true
    fi
}

# ============== 端口占用检测 ==============
check_port_conflict() {
    local port="$1"
    local conflict=""
    if ss -tlnp 2>/dev/null | grep -qE ":${port}\b"; then conflict="TCP"; fi
    if ss -ulnp 2>/dev/null | grep -qE ":${port}\b"; then
        [[ -n "$conflict" ]] && conflict="TCP+UDP" || conflict="UDP"
    fi
    if [[ -n "$conflict" ]]; then
        warn "本机端口 ${port} 已被其他服务占用（${conflict}）。"
        warn "添加转发后，该端口的外部流量将被转发，本地服务可能无法从外部访问。"
        read -rp "是否仍要继续添加转发规则？[y/N]: " ans
        [[ "$ans" =~ ^[Yy]$ ]] || return 1
    fi
    return 0
}

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
    local pending_note="" line
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*备注:[[:space:]]*(.*)$ ]]; then
            pending_note=$(sanitize_note "${BASH_REMATCH[1]}")
            continue
        fi
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ tcp[[:space:]]+dport[[:space:]]+([0-9]+)[[:space:]]+dnat[[:space:]]+to[[:space:]]+([0-9.]+):([0-9]+) ]]; then
            RULES+=("${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|${BASH_REMATCH[3]}|${pending_note}")
            pending_note=""
        fi
    done < "${CONF_FILE}"
}

write_conf_file() {
    local local_ip
    local_ip=$(get_local_ip)
    [[ -n "$local_ip" ]] || local_ip=$(get_conf_local_ip)
    if [[ -z "$local_ip" ]]; then
        err "无法获取本机 IP 地址，请检查网络配置。"
        return 1
    fi

    local tmp_file="${CONF_FILE}.tmp.$$"
    cat > "${tmp_file}" <<EOF
#!/usr/sbin/nft -f

# --- 本机 IP（自动获取，用于 SNAT 回源）
define LOCAL_IP = ${local_ip}

table ip ${TABLE_NAME} {
    # --- PREROUTING (DNAT) ---
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
EOF

    local rule lport dip dport note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        cat >> "${tmp_file}" <<EOF

        # 转发: 本机:${lport} -> ${dip}:${dport}
EOF
        if [[ -n "$note" ]]; then
            cat >> "${tmp_file}" <<EOF
        # 备注: ${note}
EOF
        fi
        cat >> "${tmp_file}" <<EOF
        tcp dport ${lport} dnat to ${dip}:${dport}
        udp dport ${lport} dnat to ${dip}:${dport}
EOF
    done

    cat >> "${tmp_file}" <<EOF
    }

    # --- POSTROUTING (SNAT) ---
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
EOF

    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        cat >> "${tmp_file}" <<EOF

        # 回源: 发往 ${dip}:${dport} 的已 DNAT 流量, SNAT 为本机 IP
        ip daddr ${dip} tcp dport ${dport} ct status dnat snat to \$LOCAL_IP
        ip daddr ${dip} udp dport ${dport} ct status dnat snat to \$LOCAL_IP
EOF
    done

    cat >> "${tmp_file}" <<EOF
    }
}
EOF

    mv -f "${tmp_file}" "${CONF_FILE}" 2>/dev/null || {
        err "无法写入配置文件 ${CONF_FILE}"
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
}

init_conf() {
    mkdir -p "${CONF_DIR}" "${BACKUP_DIR}" 2>/dev/null || {
        err "无法创建配置目录 ${CONF_DIR}，请检查权限。"
        return 1
    }
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
        info "已创建 ${MAIN_CONF}（系统中不存在该文件）。"
        log_action "创建 ${MAIN_CONF}"
    elif ! grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
        echo 'include "/etc/nftables.d/*.conf"' >> "${MAIN_CONF}"
        info "已在 ${MAIN_CONF} 中添加 include 指令。"
        log_action "在 ${MAIN_CONF} 中添加 include 指令"
    fi
    if [[ ! -f "${CONF_FILE}" ]]; then
        write_conf_file || return 1
    fi
}

reload_rules() {
    nft flush table ip "${TABLE_NAME}" 2>/dev/null || true
    nft delete table ip "${TABLE_NAME}" 2>/dev/null || true
    if ! nft -f "${CONF_FILE}"; then
        err "加载配置文件失败，请检查 ${CONF_FILE}"
        return 1
    fi
    return 0
}

backup_conf() {
    if [[ -f "${CONF_FILE}" ]]; then
        local ts
        ts=$(date '+%Y%m%d_%H%M%S')
        cp "${CONF_FILE}" "${BACKUP_DIR}/port-forward.conf.${ts}" 2>/dev/null || true
    fi
}

enable_ip_forward() {
    local current
    current=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || current="0"
    if [[ "$current" != "1" ]]; then
        if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
            info "已开启 IPv4 转发。"
        else
            warn "无法开启 IPv4 转发，请手动执行: sysctl -w net.ipv4.ip_forward=1"
        fi
    fi
    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    touch "${SYSCTL_CONF}" 2>/dev/null || true
    if grep -qE '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "${SYSCTL_CONF}" 2>/dev/null; then
        sed -i -E 's|^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*|net.ipv4.ip_forward=1|' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.ipv4.ip_forward=1" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi
    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
}

enable_bbr_fq() {
    modprobe tcp_bbr 2>/dev/null || true
    if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        warn "内核不支持 BBR（tcp_available_congestion_control 中未找到 bbr），已跳过。"
        return 0
    fi
    local cur_cc cur_qd
    cur_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || cur_cc=""
    cur_qd=$(sysctl -n net.core.default_qdisc 2>/dev/null) || cur_qd=""
    if [[ "$cur_cc" == "bbr" && "$cur_qd" == "fq" ]]; then
        info "BBR + fq 已启用（无需修改）。"
        return 0
    fi
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    cur_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || cur_cc=""
    cur_qd=$(sysctl -n net.core.default_qdisc 2>/dev/null) || cur_qd=""
    if [[ "$cur_cc" == "bbr" && "$cur_qd" == "fq" ]]; then
        info "已开启 BBR + fq。"
        log_action "开启 BBR+fq"
    else
        warn "尝试开启 BBR+fq 后未确认生效（当前: cc=${cur_cc:-?}, qdisc=${cur_qd:-?}），可能被系统配置覆盖。"
    fi
    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    touch "${SYSCTL_CONF}" 2>/dev/null || true
    if grep -qE '^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=' "${SYSCTL_CONF}"; then
        sed -i -E 's|^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=.*|net.core.default_qdisc=fq|' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.core.default_qdisc=fq" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi
    if grep -qE '^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=' "${SYSCTL_CONF}"; then
        sed -i -E 's/^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=.*/net.ipv4.tcp_congestion_control=bbr/' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.ipv4.tcp_congestion_control=bbr" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi
    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
    info "已持久化 BBR + fq 到 ${SYSCTL_CONF}。"
    log_action "持久化 BBR+fq 到 ${SYSCTL_CONF}"
}

check_firewall_status() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        info "检测到 firewalld 正在运行，添加转发规则时将自动放行对应端口。"
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        info "检测到 UFW 正在运行，添加转发规则时将自动放行对应端口。"
    elif has_iptables; then
        info "检测到 iptables 规则集存在，添加转发规则时将自动放行对应端口。"
    fi
}

do_diagnose() {
    echo ""
    echo "========================================"
    echo "           诊断 / 自检"
    echo "========================================"

    local ip_fwd
    ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || ip_fwd="未知"
    if [[ "$ip_fwd" == "1" ]]; then info "IPv4 转发: 已开启"; else err "IPv4 转发: 未开启 (当前值: ${ip_fwd})"; echo "  → 修复: 选择菜单【安装 nftables】会自动开启"; fi

    if command -v nft &>/dev/null; then info "nftables: 已安装 ($(nft --version 2>/dev/null || echo '未知版本'))"; else err "nftables: 未安装"; echo "  → 修复: 选择菜单【安装 nftables】"; fi

    local svc_enabled svc_active
    svc_enabled=$(systemctl is-enabled nftables 2>/dev/null) || svc_enabled="unknown"
    svc_active=$(systemctl is-active nftables 2>/dev/null) || svc_active="unknown"
    [[ "$svc_enabled" == "enabled" ]] && info "nftables 开机启动: 是" || { warn "nftables 开机启动: 否（重启后规则可能丢失）"; echo "  → 修复: systemctl enable nftables"; }
    [[ "$svc_active" == "active" ]] && info "nftables 服务状态: 运行中" || { warn "nftables 服务状态: 未运行"; echo "  → 修复: systemctl start nftables"; }

    if nft list table ip "${TABLE_NAME}" &>/dev/null; then
        load_rules
        info "转发规则表: 已加载（${#RULES[@]} 条转发规则）"
    else
        warn "转发规则表: 未加载（可能无规则或服务未启动）"
    fi

    echo ""
    echo "--- 防火墙状态 ---"
    local fw_found=false
    if systemctl is-active --quiet firewalld 2>/dev/null; then fw_found=true; info "firewalld: 活跃"; fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then fw_found=true; warn "UFW: 活跃（默认会阻止入站连接，可能影响转发）"; fi
    if ! $fw_found && has_iptables; then
        fw_found=true
        local fwd_policy
        fwd_policy=$(iptables -S FORWARD 2>/dev/null | grep -- '^-P FORWARD' | awk '{print $3}') || fwd_policy=""
        if [[ "$fwd_policy" == "DROP" || "$fwd_policy" == "REJECT" ]]; then warn "iptables FORWARD 默认策略: ${fwd_policy}（可能阻止转发流量）"; else info "iptables FORWARD 默认策略: ${fwd_policy:-ACCEPT}"; fi
    fi
    if ! $fw_found; then info "未检测到活跃的防火墙 (firewalld / UFW / iptables)"; fi

    echo ""
    echo "--- nftables forward 链 ---"
    local fwd_chains
    fwd_chains=$(nft list chains 2>/dev/null | grep -B1 "hook forward") || true
    if [[ -n "$fwd_chains" ]]; then
        if echo "$fwd_chains" | grep -qi "drop"; then warn "检测到 nftables 存在 forward 链默认策略为 drop"; echo "  这会阻止所有转发流量，需手动添加放行规则。"; echo "  查看详情: nft list ruleset | grep -A5 'hook forward'"; else info "nftables forward 链: 未发现 drop 策略"; fi
    else
        info "未检测到 nftables forward 链（正常，不影响转发）"
    fi

    echo ""
    echo "--- 配置持久化 ---"
    if [[ -f "${MAIN_CONF}" ]]; then
        if grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then info "主配置 ${MAIN_CONF}: 已包含 include 指令"; else warn "主配置 ${MAIN_CONF}: 缺少 include 指令（重启后规则可能丢失）"; echo "  → 修复: 选择菜单【安装 nftables】会自动添加"; fi
    else
        warn "主配置 ${MAIN_CONF}: 不存在（重启后规则可能丢失）"
        echo "  → 修复: 选择菜单【安装 nftables】会自动创建"
    fi
    [[ -f "${CONF_FILE}" ]] && info "转发配置文件: ${CONF_FILE} 存在" || info "转发配置文件: 尚未创建（添加首条规则时自动生成）"

    echo ""
    load_rules
    if [[ ${#RULES[@]} -gt 0 ]]; then
        read -rp "是否测试目标连通性？[y/N]: " test_conn
        if [[ "$test_conn" =~ ^[Yy]$ ]]; then
            local rule lport dip dport note
            for rule in "${RULES[@]}"; do
                IFS='|' read -r lport dip dport note <<< "$rule"
                printf "  测试 %s:%s (TCP) ... " "$dip" "$dport"
                if timeout 3 bash -c ">/dev/tcp/${dip}/${dport}" 2>/dev/null; then printf "\033[32m通\033[0m\n"; else printf "\033[31m不通或超时\033[0m\n"; fi
            done
        fi
    fi
    echo ""
}

do_install() {
    echo ""
    if command -v nft &>/dev/null; then
        info "nftables 已安装。"
        nft --version 2>/dev/null || true
        echo ""
        warn "安装将清空所有已有 nftables 配置，由本脚本统一接管。"
        warn "已有的配置文件将被备份（重命名为 .bak）。"
        read -rp "是否继续？[y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then info "已取消，退出脚本。"; exit 0; fi
        local ts f
        ts=$(date '+%Y%m%d_%H%M%S')
        if [[ -f "${MAIN_CONF}" ]]; then mv "${MAIN_CONF}" "${MAIN_CONF}.bak.${ts}" 2>/dev/null || true; info "已备份 ${MAIN_CONF} → ${MAIN_CONF}.bak.${ts}"; fi
        if [[ -d "${CONF_DIR}" ]]; then
            for f in "${CONF_DIR}"/*.conf; do [[ -f "$f" ]] || continue; mv "$f" "${f}.bak.${ts}" 2>/dev/null || true; info "已备份 ${f} → ${f}.bak.${ts}"; done
        fi
        nft flush ruleset 2>/dev/null || true
        info "已清空当前 nftables 规则集。"
        log_action "清空已有配置并由脚本接管 (备份时间戳: ${ts})"
        enable_ip_forward
        enable_bbr_fq
        check_firewall_status
        init_conf
        if ! nft -f "${MAIN_CONF}"; then err "加载 ${MAIN_CONF} 失败，请检查配置。"; return; fi
        if systemctl enable --now nftables 2>/dev/null; then info "已启用 nftables 服务。"; else warn "nftables 服务启用失败，重启后规则可能丢失。"; warn "请手动执行: systemctl enable --now nftables"; fi
        info "初始化完成，所有配置已由本脚本接管。"
        return
    fi

    info "未检测到 nftables，准备安装..."
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)
    case "$pkg_mgr" in
        apt) apt-get update -y && apt-get install -y nftables ;;
        dnf) dnf install -y nftables ;;
        yum) yum install -y nftables ;;
        pacman) pacman -Sy --noconfirm nftables ;;
        *) err "无法识别包管理器，请手动安装 nftables。"; return ;;
    esac
    if ! command -v nft &>/dev/null; then err "安装失败，请手动安装 nftables。"; return; fi
    info "nftables 安装成功。"
    nft --version 2>/dev/null || true
    log_action "安装 nftables"
    enable_ip_forward
    enable_bbr_fq
    check_firewall_status
    init_conf
    if systemctl enable --now nftables 2>/dev/null; then info "已启用 nftables 服务。"; else warn "nftables 服务启用失败，重启后规则可能丢失。"; warn "请手动执行: systemctl enable --now nftables"; fi
    info "安装与初始化完成。"
}

edit_rule_note() {
    local ans
    read -rp "是否添加/修改备注？[y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] || return
    local choice
    read -rp "请输入要添加/修改备注的序号 (0 取消): " choice
    if [[ "$choice" == "0" || -z "$choice" ]]; then info "已取消。"; return; fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#RULES[@]} )); then err "无效的序号。"; return; fi
    local target="${RULES[$((choice-1))]}" lport dip dport old_note note
    IFS='|' read -r lport dip dport old_note <<< "$target"
    echo "当前规则: 本机端口 ${lport} (tcp+udp) → ${dip}:${dport}"
    echo "当前备注: ${old_note:--}"
    read -rp "请输入新备注（留空表示清空）: " note
    [[ "$note" == *"|"* ]] && warn "备注中的 | 已替换为空格。"
    note=$(sanitize_note "$note")
    backup_conf
    RULES[$((choice-1))]="${lport}|${dip}|${dport}|${note}"
    if write_conf_file; then
        [[ -n "$note" ]] && info "备注已保存: ${note}" || info "备注已清空。"
        log_action "修改备注: ${lport} -> ${dip}:${dport} 备注:${note:-无}"
    fi
}

do_list() {
    echo ""
    load_rules
    if [[ ${#RULES[@]} -eq 0 ]]; then info "当前没有端口转发规则。"; return; fi
    printf "\n\033[1m%-6s %-10s %-10s    %-22s %s\033[0m\n" "序号" "协议" "本机端口" "目标地址" "备注"
    echo "────────────────────────────────────────────────────────────────────────"
    local idx=1 rule lport dip dport note shown_note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        shown_note="${note:--}"
        printf "%-6s %-10s %-10s -> %-22s %s\n" "$idx" "tcp+udp" "$lport" "${dip}:${dport}" "$shown_note"
        ((idx++))
    done
    echo ""
    edit_rule_note
}

do_add() {
    echo ""
    if ! command -v nft &>/dev/null; then err "nftables 未安装，请先选择 [1] 安装。"; return; fi
    init_conf || return
    enable_ip_forward
    load_rules
    local local_ip
    local_ip=$(get_local_ip)
    if [[ -z "$local_ip" ]]; then err "无法获取本机 IP 地址，请检查网络配置。"; return; fi
    local lport rule rp
    while true; do read -rp "请输入本机监听端口 (1-65535): " lport; validate_port "$lport" && break; err "端口无效，请输入 1-65535 之间的数字。"; done
    for rule in "${RULES[@]}"; do IFS='|' read -r rp _ _ _ <<< "$rule"; if [[ "$rp" == "$lport" ]]; then err "本机端口 ${lport} 已存在转发规则，请先删除后再添加。"; return; fi; done
    if ! check_port_conflict "$lport"; then info "已取消。"; return; fi
    local dip dport note confirm
    while true; do read -rp "请输入目标 IP 地址: " dip; validate_ip "$dip" && break; err "IP 地址格式无效，请重新输入（如 192.168.1.100，不含前导零）。"; done
    while true; do read -rp "请输入目标端口 (1-65535) [默认: ${lport}]: " dport; dport="${dport:-$lport}"; validate_port "$dport" && break; err "端口无效，请输入 1-65535 之间的数字。"; done
    read -rp "请输入备注（可留空）: " note
    [[ "$note" == *"|"* ]] && warn "备注中的 | 已替换为空格。"
    note=$(sanitize_note "$note")
    echo ""
    echo "即将添加转发规则:"
    echo "  本机端口 ${lport} (tcp+udp) → ${dip}:${dport}"
    [[ -n "$note" ]] && echo "  备注: ${note}"
    read -rp "确认添加？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then info "已取消。"; return; fi
    backup_conf
    RULES+=("${lport}|${dip}|${dport}|${note}")
    write_conf_file || return
    if reload_rules; then
        firewall_open_port "$lport" "$dip" "$dport"
        info "转发规则添加成功: ${lport} → ${dip}:${dport}"
        log_action "新增转发: ${lport} -> ${dip}:${dport} 备注:${note:-无}"
        info "若转发不通，请使用菜单中的【诊断/自检】排查。"
    else
        err "规则加载失败，请检查配置。"
    fi
}

do_delete() {
    echo ""
    if ! command -v nft &>/dev/null; then err "nftables 未安装，请先选择 [1] 安装。"; return; fi
    load_rules
    if [[ ${#RULES[@]} -eq 0 ]]; then info "当前没有端口转发规则，无需删除。"; return; fi
    printf "\n\033[1m%-6s %-10s %-10s    %-22s %s\033[0m\n" "序号" "协议" "本机端口" "目标地址" "备注"
    echo "────────────────────────────────────────────────────────────────────────"
    local idx=1 rule lport dip dport note shown_note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        shown_note="${note:--}"
        printf "%-6s %-10s %-10s -> %-22s %s\n" "$idx" "tcp+udp" "$lport" "${dip}:${dport}" "$shown_note"
        ((idx++))
    done
    echo ""
    local choice confirm target
    read -rp "请输入要删除的序号 (0 取消): " choice
    if [[ "$choice" == "0" || -z "$choice" ]]; then info "已取消。"; return; fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#RULES[@]} )); then err "无效的序号。"; return; fi
    target="${RULES[$((choice-1))]}"
    IFS='|' read -r lport dip dport note <<< "$target"
    echo "即将删除转发规则:"
    echo "  本机端口 ${lport} (tcp+udp) → ${dip}:${dport}"
    [[ -n "$note" ]] && echo "  备注: ${note}"
    read -rp "确认删除？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then info "已取消。"; return; fi
    backup_conf
    unset 'RULES[$((choice-1))]'
    RULES=("${RULES[@]}")
    write_conf_file || return
    if reload_rules; then
        firewall_close_port "$lport" "$dip" "$dport"
        info "转发规则已删除: ${lport} → ${dip}:${dport}"
        log_action "删除转发: ${lport} -> ${dip}:${dport}"
    else
        err "规则加载失败，请检查配置。"
    fi
}

do_clear_all() {
    echo ""
    if ! command -v nft &>/dev/null; then err "nftables 未安装，请先选择 [1] 安装。"; return; fi
    load_rules
    if [[ ${#RULES[@]} -eq 0 ]]; then info "当前没有端口转发规则，无需清空。"; return; fi
    warn "即将清空全部 ${#RULES[@]} 条转发规则！"
    local confirm rule lport dip dport note
    read -rp "确认清空？[y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then info "已取消。"; return; fi
    backup_conf
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        firewall_close_port "$lport" "$dip" "$dport" "force"
    done
    RULES=()
    write_conf_file || return
    if reload_rules; then info "所有转发规则已清空。"; log_action "清空所有转发规则"; else err "规则加载失败，请检查配置。"; fi
}

main_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "   nftables 端口转发管理工具 v1.2"
        echo "========================================"
        echo "  1) 安装 nftables"
        echo "  2) 查看现有端口转发"
        echo "  3) 新增端口转发"
        echo "  4) 删除端口转发"
        echo "  5) 一键清空所有转发"
        echo "  6) 诊断/自检"
        echo "  7) 退出"
        echo "========================================"
        local choice
        read -rp "请选择操作 [1-7]: " choice
        case "$choice" in
            1) do_install ;;
            2) do_list ;;
            3) do_add ;;
            4) do_delete ;;
            5) do_clear_all ;;
            6) do_diagnose ;;
            7) info "再见！"; exit 0 ;;
            *) err "无效选择，请输入 1-7。" ;;
        esac
    done
}

check_root
main_menu
