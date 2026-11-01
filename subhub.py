#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SubHub —— 免费节点自动聚合 + 真连可用性测试 + 生成个人订阅

流程：抓取订阅源 -> 解析 vmess/vless/trojan/ss/ssr/hysteria2/tuic -> 去重
      -> 每个节点单独起引擎实例(xray / sing-box) -> SOCKS5 真连 generate_204
      -> 通过代理查询真实出口 IP -> 按出口 IP 唯一化
      -> 历史成功率 + 延迟排序 -> 输出 base64 订阅

环境变量：
  XRAY_BIN      xray 可执行文件（默认 xray）
  SINGBOX_BIN   sing-box 可执行文件（默认 sing-box，用于 hysteria2 / tuic）
  WORKERS       并发测试数（默认 8）
  PROBE_TIMEOUT 单节点探测超时秒（默认 8）
  KEEP          订阅内保留节点数（默认 80）
  UNIQUE_IP     是否按出口 IP 唯一化（默认 1）
  INCLUDE_UNPROBED  无对应引擎时是否仍保留该节点（默认 0）
"""

import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONF = ROOT / "config"
OUT = ROOT / "public"
STATE = ROOT / "state"

XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")
WORKERS = int(os.environ.get("WORKERS", "8"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "8"))
KEEP = int(os.environ.get("KEEP", "80"))
UNIQUE_IP = os.environ.get("UNIQUE_IP", "1") not in ("0", "false", "False", "")
INCLUDE_UNPROBED = os.environ.get("INCLUDE_UNPROBED", "0") in ("1", "true", "True")
MAX_NODES = int(os.environ.get("MAX_NODES", "800"))
OK_DECAY = float(os.environ.get("OK_DECAY", "0.95"))

PROBE_HOST = "www.gstatic.com"
PROBE_PATH = "/generate_204"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

XRAY_AVAILABLE = bool(shutil.which(XRAY_BIN) or Path(XRAY_BIN).exists())
SINGBOX_AVAILABLE = bool(shutil.which(SINGBOX_BIN) or Path(SINGBOX_BIN).exists())

IPV4_RE = re.compile(rb"\b((?:\d{1,3}\.){3}\d{1,3})\b")

# 出口 IP 回显源：全部走明文 80 端口，经代理请求，省去 TLS 开销
# (host, port, path, 解析方式)
IP_ECHO_SOURCES = (
    ("api.ipify.org", 80, "/", "text"),
    ("ip-api.com", 80, "/line/?fields=query", "text"),
    ("ifconfig.me", 80, "/ip", "text"),
    ("ip.3322.net", 80, "/", "text"),
)

# ------------------------------------------------- 基础工具

def b64d(s):
    s = (s or "").strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def maybe_b64(text):
    s = text.strip()
    if len(s) > 40 and re.fullmatch(r"[A-Za-z0-9+/=\s_-]+", s):
        d = b64d(s)
        if "://" in d:
            return d
    return text


def http_get(url, timeout=25, retries=3):
    """带重试与 gzip 解压；部分源会返回 Content-Encoding: gzip。"""
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Accept-Encoding": "gzip",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                enc = (r.headers.get("Content-Encoding") or "").lower()
            if "gzip" in enc:
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            return raw
        except Exception as e:
            last = e
            if i + 1 < retries:
                time.sleep(1.5 * (i + 1))
    raise last


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise OSError("eof")
        buf += c
    return buf


def split_alpn(v):
    return [a for a in re.split(r"[,\s]+", v or "") if a]


def is_routable_ip(ip):
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    if nums[0] in (0, 10, 127):
        return False
    if nums[0] == 169 and nums[1] == 254:
        return False
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return False
    if nums[0] == 192 and nums[1] == 168:
        return False
    if nums[0] == 100 and 64 <= nums[1] <= 127:
        return False
    return True


# ------------------------------------------------- DNS 回退解析（入口 IP）

_ip_cache = {}
_ip_lock = threading.Lock()


def resolve_ip(host):
    """解析节点 host 的 IP，仅在真实出口 IP 查询失败时作为回退。"""
    if not host:
        return None
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return host
        except OSError:
            pass
    with _ip_lock:
        if host in _ip_cache:
            return _ip_cache[host]
    ip = None
    try:
        infos = socket.getaddrinfo(host, None)
        for fam, _, _, _, sa in infos:
            if fam == socket.AF_INET:
                ip = sa[0]
                break
        if ip is None:
            for fam, _, _, _, sa in infos:
                ip = sa[0]
                break
    except Exception:
        ip = None
    with _ip_lock:
        _ip_cache[host] = ip
    return ip


# ------------------------------------------------- 协议解析（xray 引擎）

def build_stream(net, host, path, tls, sni, alpn, fp):
    net = (net or "tcp").lower()
    if net not in ("tcp", "ws", "grpc", "h2", "http"):
        net = "tcp"
    st = {"network": net, "security": "none"}
    if net == "ws":
        st["wsSettings"] = {"path": path or "/", "headers": {"Host": host or sni or ""}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": (path or "").lstrip("/")}
    elif net == "h2":
        st["httpSettings"] = {"path": path or "/", "host": [host or sni or ""]}
    elif net == "http":
        st["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"path": [path or "/"], "headers": {"Host": [host or sni or ""]}},
            }
        }
    if tls:
        st["security"] = "tls"
        ts = {"serverName": sni or host or "", "allowInsecure": False}
        if alpn:
            al = split_alpn(alpn)
            if al:
                ts["alpn"] = al
        if fp:
            ts["fingerprint"] = fp
        st["tlsSettings"] = ts
    return st


def parse_vmess(uri):
    body = uri[8:].split("#")[0]
    j = json.loads(b64d(body))
    host = str(j["add"]).strip("[]")
    port = int(j["port"])
    net = (j.get("net") or "tcp").lower()
    tls = str(j.get("tls", "")).lower() in ("tls", "reality", "true", "1")
    sni = j.get("sni") or j.get("host") or host
    st = build_stream(net, j.get("host", ""), j.get("path", ""), tls, sni,
                      j.get("alpn", ""), j.get("fp", ""))
    out = {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": j["id"],
                    "alterId": int(j.get("aid") or 0),
                    "security": j.get("scy") or "auto",
                }],
            }]
        },
        "streamSettings": st,
    }
    name = j.get("ps") or ("%s:%s" % (host, port))
    return host, port, out, name, "xray"


def parse_vless(uri):
    u = urllib.parse.urlsplit(uri)
    q = dict(urllib.parse.parse_qsl(u.query))
    host = (u.hostname or "").strip("[]")
    port = u.port or 443
    sec = (q.get("security") or "").lower()
    tls = sec in ("tls", "reality", "xtls")
    st = build_stream(q.get("type", "tcp"), q.get("host", ""), q.get("path", ""),
                      tls, q.get("sni") or q.get("host") or host,
                      q.get("alpn", ""), q.get("fp", ""))
    if sec == "reality":
        st["security"] = "reality"
        st["realitySettings"] = {
            "serverName": q.get("sni", "") or host,
            "fingerprint": q.get("fp", "") or "chrome",
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", "") or "/",
        }
    out = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": urllib.parse.unquote(u.username or ""),
                    "encryption": q.get("encryption", "none") or "none",
                    "flow": q.get("flow", "") or "",
                }],
            }]
        },
        "streamSettings": st,
    }
    name = urllib.parse.unquote(u.fragment) or ("%s:%s" % (host, port))
    return host, port, out, name, "xray"


def parse_trojan(uri):
    u = urllib.parse.urlsplit(uri)
    q = dict(urllib.parse.parse_qsl(u.query))
    host = (u.hostname or "").strip("[]")
    port = u.port or 443
    st = build_stream(q.get("type", "tcp"), q.get("host", ""), q.get("path", ""),
                      True, q.get("sni") or q.get("peer") or host,
                      q.get("alpn", ""), q.get("fp", ""))
    out = {
        "protocol": "trojan",
        "settings": {"servers": [{
            "address": host,
            "port": port,
            "password": urllib.parse.unquote(u.username or ""),
        }]},
        "streamSettings": st,
    }
    name = urllib.parse.unquote(u.fragment) or ("%s:%s" % (host, port))
    return host, port, out, name, "xray"


def parse_ss(uri):
    body = uri[5:]
    name = urllib.parse.unquote(body.split("#", 1)[1]) if "#" in body else ""
    body = body.split("#")[0].split("?")[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        info = b64d(userinfo)
        if ":" not in info:
            # SIP002 允许明文 percent-encoded 的 method:password
            info = urllib.parse.unquote(userinfo)
        if ":" not in info:
            return None
        method, pw = info.split(":", 1)
        u = urllib.parse.urlsplit("ss://" + hostport)
        host = (u.hostname or "").strip("[]")
        port = u.port
    else:
        dec = b64d(body)
        if "@" not in dec:
            return None
        info, hostport = dec.rsplit("@", 1)
        if ":" not in info or ":" not in hostport:
            return None
        method, pw = info.split(":", 1)
        host, p = hostport.rsplit(":", 1)
        host = host.strip("[]")
        port = int(p)
    if not host or not port:
        return None
    out = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": host,
            "port": int(port),
            "method": method,
            "password": pw,
        }]},
    }
    return host, int(port), out, (name or ("%s:%s" % (host, port))), "xray"


def parse_ssr(uri):
    """ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=&protoparam=&remarks=)"""
    body = uri[6:]
    if "#" in body:
        body = body.split("#", 1)[0]
    dec = b64d(body)
    if not dec:
        return None
    if "/?" in dec:
        main, qs = dec.split("/?", 1)
    else:
        main, qs = dec, ""
    # 注意：[::1]:8388:origin:... 里主机自带冒号，rsplit 会切错，先单独处理方括号形式
    if main.startswith("["):
        end = main.find("]")
        if end < 0:
            return None
        host = main[1:end]
        rest = main[end + 1:]
        if rest.startswith(":"):
            rest = rest[1:]
        parts = rest.split(":", 4)
        if len(parts) != 5:
            return None
        port, protocol, method, obfs, pw_b64 = parts
    else:
        parts = main.split(":", 5)
        if len(parts) != 6:
            return None
        host, port, protocol, method, obfs, pw_b64 = parts
    host = host.strip("[]")
    try:
        port = int(port)
    except ValueError:
        return None
    if not host or not port:
        return None
    pw = b64d(pw_b64) or pw_b64
    q = {}
    for kv in qs.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            dv = b64d(v)
            q[k] = dv if dv else urllib.parse.unquote(v)
    out = {
        "protocol": "shadowsocksr",
        "settings": {"servers": [{
            "address": host,
            "port": port,
            "method": method,
            "password": pw,
            "protocol": protocol,
            "protocolParam": q.get("protoparam", ""),
            "obfs": obfs,
            "obfsParam": q.get("obfsparam", ""),
        }]},
        "streamSettings": {"network": "tcp", "security": "none"},
    }
    name = q.get("remarks") or ("%s:%s" % (host, port))
    return host, port, out, name, "xray"


# ------------------------------------------------- 协议解析（sing-box 引擎）

def sb_tls(q, default_alpn=None, default_sni=""):
    insecure = str(q.get("insecure", "")).lower() in ("1", "true", "yes")
    tls = {"enabled": True, "insecure": insecure}
    sni = q.get("sni") or q.get("peer") or default_sni
    if sni:
        tls["server_name"] = sni
    al = split_alpn(q.get("alpn", "")) or (default_alpn or [])
    if al:
        tls["alpn"] = al
    fp = q.get("fp") or q.get("fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls


def parse_hysteria2(uri):
    """hysteria2:// 或 hy2://  password@host:port?insecure=1&sni=&obfs=salamander&obfs-password="""
    u = urllib.parse.urlsplit(uri)
    q = dict(urllib.parse.parse_qsl(u.query))
    host = (u.hostname or "").strip("[]")
    port = u.port or 443
    if not host or not port:
        return None
    pw = urllib.parse.unquote(u.username or "")
    if u.password:
        pw = pw + ":" + urllib.parse.unquote(u.password)
    out = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "password": pw,
        "tls": sb_tls(q, default_alpn=["h3"]),
    }
    obfs = q.get("obfs")
    if obfs:
        op = (q.get("obfs-password") or q.get("obfs_password")
              or q.get("obfsParam") or q.get("obfs-param") or "")
        out["obfs"] = {"type": obfs, "password": op}
    name = urllib.parse.unquote(u.fragment) or ("%s:%s" % (host, port))
    return host, int(port), out, name, "singbox"


def parse_tuic(uri):
    """tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni="""
    u = urllib.parse.urlsplit(uri)
    q = dict(urllib.parse.parse_qsl(u.query))
    host = (u.hostname or "").strip("[]")
    port = u.port or 443
    if not host or not port:
        return None
    uuid = urllib.parse.unquote(u.username or "")
    pw = urllib.parse.unquote(u.password or "")
    out = {
        "type": "tuic",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "uuid": uuid,
        "password": pw,
        "congestion_control": q.get("congestion_control") or q.get("congestion") or "bbr",
        "udp_relay_mode": q.get("udp_relay_mode") or "native",
        "tls": sb_tls(q, default_alpn=["h3"]),
    }
    name = urllib.parse.unquote(u.fragment) or ("%s:%s" % (host, port))
    return host, int(port), out, name, "singbox"


PARSERS = (
    ("vmess://", parse_vmess),
    ("vless://", parse_vless),
    ("trojan://", parse_trojan),
    ("ssr://", parse_ssr),
    ("ss://", parse_ss),
    ("hysteria2://", parse_hysteria2),
    ("hy2://", parse_hysteria2),
    ("tuic://", parse_tuic),
)


def parse_uri(uri):
    for prefix, fn in PARSERS:
        if uri.startswith(prefix):
            try:
                r = fn(uri)
            except Exception:
                return None
            if not r or not r[0] or not r[1]:
                return None
            host, port, out, name, engine = r
            proto = out.get("protocol") or out.get("type") or ""
            # 用完整出站对象的规范化哈希做去重键：同 host:port 但不同 uuid / 密码 /
            # sni / reality pbk / grpc serviceName 的是不同节点，不能被互相覆盖丢掉
            blob = proto + "|" + json.dumps(out, sort_keys=True,
                                            ensure_ascii=False, separators=(",", ":"))
            key = hashlib.sha1(blob.encode("utf-8")).hexdigest()
            return {
                "key": key, "uri": uri, "out": out, "name": name,
                "host": host, "port": port, "proto": proto, "engine": engine,
            }
    return None


# ------------------------------------------------- 抓取

def collect():
    src = CONF / "sources.txt"
    urls = []
    if src.exists():
        for line in src.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    lines = []
    for url in urls:
        try:
            raw = http_get(url)
            txt = maybe_b64(raw.decode("utf-8", "ignore"))
            n = 0
            for line in txt.splitlines():
                line = line.strip()
                if "://" in line and not line.startswith("#"):
                    lines.append(line)
                    n += 1
            print("[+] %-70s %5d 行" % (url[:70], n))
        except Exception as e:
            print("[!] %-70s %s" % (url[:70], e))
    return lines


# ------------------------------------------------- 引擎启动

def start_engine(engine, outbound, port):
    if engine == "singbox":
        cfg = {
            "log": {"level": "error", "timestamp": False},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [outbound],
        }
        binary = SINGBOX_BIN
        wait = 6.0
    else:
        cfg = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"udp": False, "auth": "noauth"},
            }],
            "outbounds": [outbound],
        }
        binary = XRAY_BIN
        wait = 4.0
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen([binary, "run", "-c", path],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    deadline = time.time() + wait
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("%s exited" % engine)
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return proc, path
        except OSError:
            time.sleep(0.08)
    raise RuntimeError("%s timeout" % engine)


# ------------------------------------------------- SOCKS5 通道

def socks5_http(port, host, path, timeout, dst_port=80):
    """经本地 SOCKS5 以域名方式 CONNECT 到 host:dst_port，发一个 HTTP/1.1 GET。"""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if recvn(s, 2) != b"\x05\x00":
            return None
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", dst_port))
        hdr = recvn(s, 4)
        if hdr[1] != 0:
            return None
        atyp = hdr[3]
        if atyp == 1:
            recvn(s, 4 + 2)
        elif atyp == 3:
            n = recvn(s, 1)[0]
            recvn(s, n + 2)
        elif atyp == 4:
            recvn(s, 16 + 2)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n" % (path, host, UA))
        s.sendall(req.encode())
        data = b""
        while len(data) < 8192:
            c = s.recv(1024)
            if not c:
                break
            data += c
        return data
    finally:
        s.close()


def get_exit_ip(port, timeout):
    """经代理真实查询出口 IP；多个回显源轮换，全部失败返回 None。"""
    for host, dport, path, _ in IP_ECHO_SOURCES:
        try:
            data = socks5_http(port, host, path, timeout, dport)
        except Exception:
            continue
        if not data or not re.match(rb"HTTP/1\.[01] (200|301|302)", data):
            continue
        body = data.split(b"\r\n\r\n", 1)[-1]
        m = IPV4_RE.search(body)
        if m:
            ip = m.group(1).decode()
            if is_routable_ip(ip):
                return ip
    return None


# ------------------------------------------------- 测活

def probe(node):
    """返回 (延迟秒 或 None, 出口 IP 或 None)。"""
    proc = path = None
    best = None
    exit_ip = None
    port = None
    try:
        # free_port() 是 bind(0)+close()，并发下有 TOCTOU 竞态：两个线程可能拿到同一端口，
        # 后启动的引擎绑定失败会被误判成死节点。绑定失败就换端口重试。
        started = False
        for _ in range(3):
            port = free_port()
            try:
                proc, path = start_engine(node["engine"], node["out"], port)
                started = True
                break
            except Exception:
                proc = path = None
        if not started:
            return None, None

        # 连续两次探测取最小延迟：失败不覆盖 best，也不提前 break（原实现恒定只探一次）
        for _ in range(2):
            t0 = time.time()
            try:
                data = socks5_http(port, PROBE_HOST, PROBE_PATH, TIMEOUT)
            except Exception:
                data = None
            if data and re.match(rb"HTTP/1\.[01] (200|204|301|302)", data):
                dt = time.time() - t0
                best = dt if best is None else min(best, dt)
            else:
                time.sleep(0.15)
        if best is not None:
            exit_ip = get_exit_ip(port, TIMEOUT)
        return best, exit_ip
    except Exception:
        return None, None
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


# ------------------------------------------------- 历史状态

def load_state():
    p = STATE / "seen.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")


# ------------------------------------------------- 主流程

def main():
    if not XRAY_AVAILABLE:
        print("[x] 找不到 xray 可执行文件（XRAY_BIN=%s）" % XRAY_BIN)
        return 2
    if not SINGBOX_AVAILABLE:
        print("[!] 未找到 sing-box（SINGBOX_BIN=%s）：hysteria2/tuic 节点将无法测活" % SINGBOX_BIN)

    print("== 1. 抓取订阅源 ==")
    raw_lines = collect()
    print("   原始行数: %d" % len(raw_lines))

    print("== 2. 解析 + 去重 ==")
    nodes = {}
    proto_stat = {}
    for line in raw_lines:
        n = parse_uri(line)
        if n and n["key"] not in nodes:
            nodes[n["key"]] = n
            proto_stat[n["proto"]] = proto_stat.get(n["proto"], 0) + 1
    print("   去重后节点: %d  %s" % (len(nodes), json.dumps(proto_stat, ensure_ascii=False)))
    if not nodes:
        print("[x] 没有解析出任何节点，检查 sources.txt")
        return 1

    print("== 3. 真连可用性测试（%d 并发）==" % WORKERS)
    history = load_state()
    results = []
    skipped = 0
    ip_unknown = 0
    todo = []
    for n in nodes.values():
        if n["engine"] == "singbox" and not SINGBOX_AVAILABLE:
            skipped += 1
            if INCLUDE_UNPROBED:
                n["latency"] = 999.0
                n["exit_ip"] = None
                results.append(n)
            continue
        todo.append(n)

    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(probe, n): n for n in todo}
        for fu in as_completed(futs):
            node = futs[fu]
            lat, exit_ip = fu.result()
            done += 1
            if done % 20 == 0:
                print("   进度 %d/%d，已存活 %d" % (done, len(futs), len(results)))
            if lat is None:
                continue
            h = history.get(node["key"], {"ok": 0, "fail": 0})
            h["ok"] = h.get("ok", 0) + 1
            h["last_ok"] = int(time.time())
            h["latency"] = round(lat, 3)
            history[node["key"]] = h
            node["latency"] = lat
            if exit_ip:
                node["exit_ip"] = exit_ip
                node["ip_src"] = "echo"
            else:
                fb = resolve_ip(node["host"])
                node["exit_ip"] = fb
                node["ip_src"] = "dns" if fb else "none"
                ip_unknown += 1
            results.append(node)

    alive_keys = {n["key"] for n in results}
    for n in nodes.values():
        if n["key"] not in history:
            history[n["key"]] = {"ok": 0, "fail": 0}
        if n["key"] not in alive_keys:
            history[n["key"]]["fail"] = history[n["key"]].get("fail", 0) + 1

    print("   存活: %d / %d（跳过未测活 %d，出口IP回退DNS %d）"
          % (len(results), len(nodes), skipped, ip_unknown))
    if not results:
        print("[x] 本轮无可用节点，保留上一次订阅不覆盖")
        save_json(STATE / "seen.json", history)
        return 1

    def score(n):
        h = history.get(n["key"], {})
        ok = h.get("ok", 0)
        fail = h.get("fail", 0)
        bonus = min(ok, 25) * 0.12       # 历史稳定最多 -3s
        penalty = min(fail, 50) * 0.05   # 历史失败最多 +2.5s
        return n["latency"] - bonus + penalty

    results.sort(key=score)

    # ---------- 唯一出口 IP 去重：同 IP 只保留分数最优的一个 ----------
    dup_removed = 0
    if UNIQUE_IP:
        seen_ip = set()
        uniq = []
        for n in results:
            ip = n.get("exit_ip")
            k = ip if ip else ("unknown:" + n["host"])
            if k in seen_ip:
                dup_removed += 1
                continue
            seen_ip.add(k)
            uniq.append(n)
        results = uniq
        print("   唯一出口 IP 去重: 移除 %d 个同 IP 节点，剩 %d"
              % (dup_removed, len(results)))

    keep = results[:max(1, KEEP)]   # 防止 KEEP<=0 导致空订阅 / 后续除零

    print("== 4. 输出订阅 ==")
    body = "\n".join(n["uri"] for n in keep) + "\n"
    b64 = base64.b64encode(body.encode()).decode()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sub_base64.txt").write_text(b64 + "\n", encoding="utf-8")
    (OUT / "sub_raw.txt").write_text(body, encoding="utf-8")
    save_json(OUT / "stats.json", {
        "updated": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "scraped": len(raw_lines),
        "parsed": len(nodes),
        "protocols": proto_stat,
        "alive": len(results) + (skipped if INCLUDE_UNPROBED else 0),
        "unprobed_skipped": skipped,
        "exit_ip_fallback_dns": ip_unknown,
        "unique_ip": UNIQUE_IP,
        "ip_duplicates_removed": dup_removed,
        "published": len(keep),
        "avg_latency": round(sum(n["latency"] for n in keep) / len(keep), 3),
        "best": [
            {"name": n["name"][:60], "host": n["host"], "port": n["port"],
             "exit_ip": n.get("exit_ip"), "ip_src": n.get("ip_src"),
             "latency": round(n["latency"], 3), "proto": n["proto"],
             "engine": n["engine"],
             "history_ok": history.get(n["key"], {}).get("ok", 0)}
            for n in keep[:10]
        ],
    })
    save_json(STATE / "seen.json", history)
    print("   已发布 %d 个节点 -> public/sub_base64.txt" % len(keep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
