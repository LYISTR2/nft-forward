# nft-forward

基于 nftables 的交互式 IPv4 端口转发管理工具。支持 DNAT/SNAT、按端口双向流量统计、月度流量限制、超限自动停止转发，以及每月自动重置。

## 一键运行

推荐使用进程替换，保留终端输入给交互菜单：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/LYISTR2/nft-forward/main/nft-forward.sh)
```

不建议使用 `wget -O- ... | bash`，因为交互式脚本通过管道运行时无法继续从终端读取菜单输入。

## 安装到本地

```bash
curl -fsSL -o /usr/local/bin/nft-forward https://raw.githubusercontent.com/LYISTR2/nft-forward/main/nft-forward.sh
```

```bash
chmod +x /usr/local/bin/nft-forward
```

```bash
nft-forward
```

## 主要功能

- 安装并初始化 nftables
- 新增、查看、删除 TCP + UDP 端口转发
- 自动生成 DNAT 与 SNAT 回源规则
- 按本机转发端口分别统计上传、下载及总流量
- 自动识别默认网卡，并显示整机 RX/TX 流量
- 每条端口规则可设置独立的月流量限制
- 达到流量限制后，自动丢弃该端口后续转发流量
- 每月 1 日 00:00 自动清零统计并恢复被限额停止的转发
- 支持手动重置流量
- 支持为每条转发指定入站网卡，或使用 `auto` 自动识别
- 自动开启 IPv4 转发
- 尝试启用 BBR + fq
- 写入 `/etc/nftables.d/port-forward.conf`
- 自动备份旧配置、记录操作日志
- 诊断 nftables、网卡、计数表和月度重置 timer

## 流量统计口径

每条端口转发会创建两组 nftables named counter：

- `upload_<本机端口>`：客户端发往目标服务器的流量
- `download_<本机端口>`：目标服务器返回客户端的流量

月度限额按这两方向的总流量计算，即：

```text
月流量 = 上传 + 下载
```

统计位于 nftables `forward` hook，匹配 `ct status dnat` 和连接的原始目标端口，因此不会把目标服务器上相同端口的其他普通流量混入统计。

## 流量限制

新增规则时可以直接填写：

```text
500G
2T
1024M
0
```

- `0` 表示不限流量。
- 支持 `B / K / M / G / T`，按 1024 进制换算。
- 达到限额后，nftables quota 会立即丢弃该端口后续转发数据包。
- 手动重置或月度 timer 执行后，计数和 quota 同时清零，转发自动恢复。
- 修改规则或限额会重建 nftables 计数对象，该端口会从 0 重新统计。

## 网卡识别

脚本通过默认 IPv4 路由自动识别网卡，例如：

```text
eth0
ens3
enp1s0
```

新增规则默认使用 `auto`。也可以在菜单中为某条规则指定固定的入站网卡。

“查看流量统计”中还会显示默认网卡自身的 RX/TX，但这是整台服务器的总流量，仅用于参考；端口限额只以 nftables 的端口计数为准。

## 月度自动重置

脚本安装 systemd timer：

```text
nft-forward-reset.timer
```

默认执行时间：

```text
每月 1 日 00:00
```

timer 使用 `Persistent=true`。如果服务器在重置时间关机，开机后会补执行一次。

即使通过 `bash <(curl ...)` 临时运行，脚本也会在启用 timer 前把经过语法校验的当前版本安装到 `/usr/local/bin/nft-forward`。

查看状态：

```bash
systemctl status nft-forward-reset.timer
```

查看下次执行时间：

```bash
systemctl list-timers nft-forward-reset.timer
```

## 命令行用法

```bash
# 查看每端口流量
nft-forward --traffic
```

```bash
# 手动清零本月统计并恢复超限端口
nft-forward --reset-traffic
```

```bash
# 安装或修复月度重置 timer
nft-forward --install-timer
```

```bash
# 诊断
nft-forward --diagnose
```

```bash
# 帮助
nft-forward --help
```

## 菜单

```text
  1) 安装 / 初始化 nftables
  2) 查看端口转发规则
  3) 新增端口转发
  4) 删除端口转发
  5) 清空所有转发
  6) 查看流量统计
  7) 设置端口月流量限制
  8) 设置端口入站网卡
  9) 手动重置本月流量
 10) 修改规则备注
 11) 诊断 / 自检
 12) 退出
```

## 配置和状态

```text
/etc/nftables.conf
/etc/nftables.d/port-forward.conf
/etc/nftables.d/backups/
/etc/sysctl.d/99-nft-forward.conf
/etc/systemd/system/nft-forward-reset.service
/etc/systemd/system/nft-forward-reset.timer
/var/log/nft-forward.log
```

流量统计和限额状态保存在运行中的 nftables named counter/quota 中。系统重启加载配置后，从 0 开始统计当前周期流量；每月 timer 也会主动清零。

## 注意事项

- 需要 root 权限。
- 当前只支持 IPv4。
- 每条规则同时创建 TCP 和 UDP 转发。
- 菜单中的“安装 / 初始化 nftables”仍会接管并清空已有 nftables 配置；执行前会提示确认并备份配置文件。
- 如果服务器同时启用了 firewalld、UFW 或 iptables，脚本会尝试放行对应端口。
- 需要 nftables 支持 named counters、named quotas、`ct original proto-dst` 与 JSON 输出；建议使用较新的 Debian、Ubuntu、Rocky Linux 或 Arch Linux。
- `--traffic` 使用 Python 3 解析 `nft -j` 输出；安装流程会尝试安装 Python 3。
- nftables 统计的是 IP 数据包字节数，不等同于应用层有效载荷，也可能与服务商控制台的链路层计费略有差异。
- 若转发规则被其他工具整表覆盖，计数与 quota 会丢失，需要重新加载本项目配置。
