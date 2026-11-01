# SubHub —— 自用免费节点聚合订阅

每天自动：抓取多个公开免费节点源 → 解析去重 → **真连测活**（不是 ping）→ **按出口 IP 唯一化** → 按历史稳定性排序 → 生成自己的订阅地址。

## 支持的协议

| 协议 | 解析 | 测活引擎 |
|---|---|---|
| vmess | ✅ | xray |
| vless（含 reality / ws / grpc / h2 / http） | ✅ | xray |
| trojan | ✅ | xray |
| shadowsocks（`userinfo@` 与整串 base64 两种编码） | ✅ | xray |
| shadowsocksr（ssr，含 obfsparam / protoparam） | ✅ | xray |
| hysteria2 / hy2（含 salamander obfs） | ✅ | sing-box |
| tuic（v5，congestion_control / udp_relay_mode） | ✅ | sing-box |

> hysteria2 / tuic 是 UDP + QUIC 协议，xray 不支持，因此走 sing-box 出站。若环境里没有 sing-box，这些节点会被跳过（不会污染订阅），并把跳过数量写进 `stats.json`。

## 一、部署（3 分钟）

1. 在 GitHub 新建一个**公开**仓库，命名随意，比如 `subhub`。
2. 把本目录所有文件（含 `.github/`）推上去：

```bash
cd subhub
git init -b su
git add -A
git commit -m "init"
git remote add origin https://github.com/<你的用户名>/subhub.git
git push -u origin su
```

3. 仓库 → Settings → Actions → General → Workflow permissions → 选 **Read and write permissions** → Save。
4. 仓库 → Actions → `subhub` → Run workflow 手动跑一次。
5. 跑完（约 10~30 分钟）后，`public/` 下会生成结果。

## 二、你的订阅地址

```
https://raw.githubusercontent.com/<用户名>/subhub/su/public/sub_base64.txt
```

- 可直接丢进 v2rayN / Shadowrocket / NekoBox / sing-box；Clash 需先经 subconverter 转换。
- Clash 格式：

```
https://<你的-subconverter>/sub?target=clash&url=<上面那个 raw 地址>&insert=false&emoji=true&list=false&udp=true
```

- jsDelivr 加速：`https://cdn.jsdelivr.net/gh/<用户名>/subhub@su/public/sub_base64.txt`

## 三、仓库结构

```
subhub.py                     主程序：抓取 / 解析 / 测活 / IP 唯一化 / 输出
config/sources.txt            订阅源列表（自己增删）
public/sub_base64.txt         成品订阅（base64）
public/sub_raw.txt            明文节点列表
public/stats.json             本轮统计（协议分布、存活数、IP 去重数、Top10）
state/seen.json               历史成功率库，用于"稳定节点优先"
.github/workflows/update.yml  定时任务（自动装 xray + sing-box）
```

## 四、可调参数

workflow 的 `env` 里改：

| 变量 | 默认 | 说明 |
|---|---|---|
| `WORKERS` | 10 | 并发测速数，越大越快但吃 CPU |
| `PROBE_TIMEOUT` | 8 | 单节点探测超时（秒） |
| `KEEP` | 80 | 订阅最终保留多少节点 |
| `UNIQUE_IP` | 1 | 是否按出口 IP 唯一化（同一 IP 只留最快的一个） |
| `INCLUDE_UNPROBED` | 0 | 无 sing-box 时是否仍保留未测活的 hysteria2/tuic |
| `XRAY_BIN` | xray | xray 可执行文件路径 |
| `SINGBOX_BIN` | sing-box | sing-box 可执行文件路径 |

`cron: "17 */6 * * *"` 改成 `"17 3 * * *"` 即每天一次。

## 五、原理：为什么不用 ping

免费节点里大量是"端口开着但隧道不通"的假活。判定标准：

1. 给每个节点单独起一个引擎进程（xray 或 sing-box），监听随机本地端口作为 SOCKS5 入口；
2. 通过该 SOCKS5 真实访问 `http://www.gstatic.com/generate_204`（手写 SOCKS5 握手，域名型 CONNECT）；
3. 必须拿到 `HTTP 204`（或 200/30x）才算活；
4. 连续两次探测取最小延迟，剔除抖动节点；
5. `state/seen.json` 记录累计成功次数，历史越稳排越前——"提前可用"的节点自动顶到订阅顶部。

排序公式：

```
score = 延迟 - min(历史成功次数, 25) × 0.12
```

### 出口 IP 唯一化

免费源里同一台机器常被反复分发（不同端口 / 不同名字 / 不同协议）。所以去重不能用入口域名，必须看真实出口。

测活成功后，脚本复用同一条已建立的 SOCKS5 通道，向 `api.ipify.org`、`ip-api.com`、`ifconfig.me`、`ip.3322.net`（均为明文 80 端口，省去 TLS 开销）依次查询回显 IP，取第一个合法公网 IPv4：

- 回显成功：`ip_src = "echo"`，这是真实出口 IP；
- 全部回显失败：退化为对节点 `host` 做 DNS 解析（`ip_src = "dns"`），这只能算入口 IP，属于兜底；
- 两者都拿不到：`ip_src = "none"`，键退化为 `unknown:<host>`。

回显结果会过一遍 `is_routable_ip()`，剔除 `10./127./169.254./192.168./172.16-31./100.64-127.` 等私网与保留段，避免代理自身的内网地址被当成"唯一出口"。

然后按 score 顺序遍历，**同一出口 IP 只保留分数最优的那一个**，其余丢弃。丢弃数量写进 `stats.json` 的 `ip_duplicates_removed`，回显失败次数写进 `exit_ip_fallback_dns`。这样订阅里 80 个节点就是 80 个不同出口，不会出现"一堆节点其实是同一台机器"的假多样性。

## 六、手机 Termux 本地跑（可选）

```bash
pkg install python xray sing-box cronie
cd /sdcard/subhub
XRAY_BIN=$PREFIX/bin/xray SINGBOX_BIN=$PREFIX/bin/sing-box python3 subhub.py
crond   # 配 crontab -e 加定时
```

产物同样是 `public/sub_base64.txt`，用本地文件服务器或 Git 同步出去即可。

## 七、注意事项

- 免费节点**随时会死**，本项目的价值是每天替你筛掉死掉的，不保证长期可用。
- 节点源都是公开仓库，质量参差，不要用它们登录任何重要账号。
- 想更稳，把你自己付费机场订阅加进 `config/sources.txt`，脚本会一视同仁测速合并。
- `ssr` 用的 `shadowsocksr` 出站需要 xray 支持；若你的 xray 版本已移除 SSR，该协议节点会自动测活失败并被剔除，不影响其它节点。
