# nft-forward

nftables 端口转发管理工具，支持交互式管理 DNAT 端口转发规则。

## 一键运行

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/LYISTR2/nft-forward/main/nft-forward.sh)
```

如果系统没有 `curl`，可以使用：

```bash
wget -O- https://raw.githubusercontent.com/LYISTR2/nft-forward/main/nft-forward.sh | bash
```

## 功能

- 安装并初始化 nftables
- 新增 TCP + UDP 端口转发
- 查看现有端口转发
- 删除单条端口转发
- 一键清空全部转发
- 诊断 / 自检
- 自动开启 IPv4 转发
- 尝试启用 BBR + fq
- 自动写入 `/etc/nftables.d/port-forward.conf`
- 自动备份旧配置

## 注意

- 需要 root 权限运行。
- 菜单中的“安装 nftables”会提示确认，并接管 nftables 配置；已有配置会先备份。
- 如果服务器同时启用了 firewalld / UFW / iptables，脚本会尝试自动放行对应端口。

## 手动安装到本地

```bash
curl -fsSL -o /usr/local/bin/nft-forward https://raw.githubusercontent.com/LYISTR2/nft-forward/main/nft-forward.sh
chmod +x /usr/local/bin/nft-forward
nft-forward
```
