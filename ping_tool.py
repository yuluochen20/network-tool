# -*- coding: utf-8 -*-
"""
批量Ping + 局域网设备发现工具  v2
- 网段批量 ping，16x16 红绿网格，窗口可自由缩放（网格与字号自适应）
- 悬浮显示 IP / 状态 / 延迟；单击打开长 ping 窗口；右键菜单可打开网页
- 局域网设备发现：ping 扫段 + ARP 表 + 端口扫描 + RTSP/HTTP 指纹，
  可识别海康威视、大华等视频监控设备
- 批量结果、设备清单均可导出 CSV 报表
"""
import csv
import json
import os
import queue
import re
import select
import socket
import struct
import subprocess
import threading
import time
import tkinter as tk
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk, filedialog, messagebox

CREATE_NO_WINDOW = 0x08000000  # 隐藏 ping 的控制台窗口

# 上次发现过的设备（对标 ConfigTool：重启后仍能看到上次的设备，灰色＝未验证在线）
HIST_PATH = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"),
                         "BatchPing", "devices.json")


def load_history():
    try:
        with open(HIST_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_history(data):
    try:
        os.makedirs(os.path.dirname(HIST_PATH), exist_ok=True)
        tmp = HIST_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, HIST_PATH)
    except Exception:
        pass

COLOR_ONLINE = "#00A000"
COLOR_OFFLINE = "#CC0000"
COLOR_IDLE = "#9E9E9E"

# ---------------------------------------------------------------------------
# MAC OUI 前缀库（仅作辅助判断，最终以 RTSP / HTTP 指纹为准）
# ---------------------------------------------------------------------------
OUI_HIK = {
    "4C:BD:8F", "44:19:B6", "A4:14:37", "BC:AD:28", "C0:56:E3", "18:68:CB",
    "28:57:BE", "34:2F:6C", "48:EA:63", "58:03:FB", "68:8D:B6", "7C:C0:6C",
    "94:E1:AC", "AC:B9:2F", "B4:A3:82", "D4:EA:0D", "E0:CA:3C", "C4:2F:90",
    "44:47:CC", "08:A1:89", "24:0F:9B", "54:C4:15", "64:DB:8B", "70:E2:4C",
    "88:36:12", "A0:09:ED", "B8:3B:CC", "C8:02:8F", "DC:D2:FC", "F0:1B:6C",
}
OUI_DAHUA = {
    "3C:EF:8C", "4C:11:BF", "90:02:A9", "A0:BD:1D", "BC:32:5F", "E0:50:8B",
    "00:1C:27", "08:ED:ED", "14:A7:8B", "24:DA:9B", "38:AF:29", "40:4D:7F",
    "68:3E:34", "84:9D:C5", "9C:14:63", "B4:4C:3B", "C4:6A:B7", "D0:52:0F",
    "E4:24:6C", "F4:4D:30", "D4:43:A8", "08:57:00",
}
OUI_OTHER = {
    "00:E0:FC": "华为", "48:46:FB": "华为", "00:18:82": "华为", "3C:CD:5D": "华为",
    "00:1A:8C": "华三/H3C", "70:F9:6D": "华三/H3C",
    "50:FA:84": "TP-Link", "A4:2B:B0": "TP-Link", "C0:25:E9": "TP-Link",
    "8C:53:C3": "小米", "64:09:80": "小米", "F0:B4:29": "小米",
    "00:0C:29": "VMware虚拟机", "00:50:56": "VMware虚拟机",
    "B8:27:EB": "树莓派", "DC:A6:32": "树莓派",
}

# 探测端口：端口 -> 含义
PROBE_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8000: "媒体流/SDK",
    37777: "大华SDK",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    34567: "P2P/私有",
    8899: "ONVIF/私有",
}


def ping_once(ip, timeout_ms=1000):
    """对单个 IP 执行一次 ping，返回 (是否在线, 延迟ms 或 None)"""
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True,
            timeout=timeout_ms / 1000.0 + 3,
            creationflags=CREATE_NO_WINDOW,
        )
        out = r.stdout.decode("gbk", errors="ignore")
        if "TTL=" in out.upper():
            m = re.search(r"[=<]\s*(\d+)\s*ms", out)
            return True, (int(m.group(1)) if m else None)
        return False, None
    except Exception:
        return False, None


def get_local_ip():
    """获取本机出口 IP（不实际发包）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "192.168.1.1"
    finally:
        s.close()


def ip_to_int(ip):
    """IPv4 字符串转整数（非法格式抛 OSError）"""
    return int.from_bytes(socket.inet_aton(ip.strip()), "big")


def int_to_ip(n):
    return socket.inet_ntoa(n.to_bytes(4, "big"))


def build_ip_range(start, end, limit=8192):
    """生成 IP 范围列表，返回 (ips, 错误信息)"""
    try:
        s, e = ip_to_int(start), ip_to_int(end)
    except OSError:
        return None, "IP 格式不正确，请填写完整地址，如 192.168.0.1"
    if e < s:
        return None, "结束 IP 不能小于起始 IP"
    count = e - s + 1
    if count > limit:
        return None, f"单次最多扫描 {limit} 个地址（当前 {count} 个），请缩小范围或分段扫描"
    return [int_to_ip(i) for i in range(s, e + 1)], None


def read_arp():
    """读取系统 ARP 表，返回 {ip: mac}"""
    table = {}
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True,
                             creationflags=CREATE_NO_WINDOW, timeout=8)
        text = out.stdout.decode("gbk", errors="ignore")
        for m in re.finditer(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})",
            text,
        ):
            ip, mac = m.group(1), m.group(2).replace("-", ":").upper()
            if mac == "00:00:00:00:00:00":
                continue
            if mac.startswith(("FF:FF:FF", "01:00:5E", "33:33")):
                continue
            table[ip] = mac
    except Exception:
        pass
    return table


def tcp_open(ip, port, timeout=0.3):
    """单端口连通性快速判断"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


def scan_ports(ip, ports=None, timeout=0.35):
    """TCP 端口扫描，返回开放端口列表"""
    ports = ports or list(PROBE_PORTS.keys())
    opened = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, p)) == 0:
                opened.append(p)
            s.close()
        except Exception:
            pass
    return opened


def decode_web(data):
    """网页内容解码：优先 UTF-8，失败回退 GBK（国产设备多为 GBK）"""
    if not data:
        return ""
    try:
        text = data.decode("utf-8")
        if "\ufffd" not in text:
            return text
    except Exception:
        pass
    try:
        return data.decode("gbk", errors="ignore")
    except Exception:
        return data.decode("utf-8", errors="ignore")


def http_probe(ip, port=80, timeout=0.8, path="/"):
    """抓取 HTTP 响应头 + 页面片段，用于厂商指纹"""
    try:
        s = socket.create_connection((ip, port), timeout)
        s.settimeout(timeout)
        s.sendall(
            f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n".encode()
        )
        data = b""
        while len(data) < 8192:
            chunk = s.recv(2048)
            if not chunk:
                break
            data += chunk
        s.close()
        return decode_web(data)
    except Exception:
        return ""


def https_probe(ip, port=443, timeout=1.2):
    """HTTPS 探测（忽略证书校验），避免把 TLS 握手包当网页解析"""
    import ssl
    try:
        ctx = ssl._create_unverified_context()
        raw = socket.create_connection((ip, port), timeout)
        s = ctx.wrap_socket(raw, server_hostname=ip)
        s.settimeout(timeout)
        s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        data = b""
        while len(data) < 8192:
            chunk = s.recv(2048)
            if not chunk:
                break
            data += chunk
        s.close()
        return decode_web(data)
    except Exception:
        return ""


def rtsp_probe(ip, port=554, timeout=0.8):
    """RTSP OPTIONS 探测，返回 Server 头等指纹"""
    try:
        s = socket.create_connection((ip, port), timeout)
        s.settimeout(timeout)
        s.sendall(
            f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
            f"User-Agent: Probe\r\n\r\n".encode()
        )
        data = s.recv(1024).decode("utf-8", errors="ignore")
        s.close()
        return data
    except Exception:
        return ""


def get_local_ips():
    """枚举本机所有 IPv4 地址（多网卡场景必须逐网卡收发组播）"""
    ips, seen = [], set()

    def add(ip):
        if not ip:
            return
        if ip.startswith(("127.", "0.", "255.", "169.254.")):
            return
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except Exception:
        pass
    try:
        out = subprocess.run(["ipconfig"], capture_output=True,
                             creationflags=CREATE_NO_WINDOW, timeout=8)
        text = out.stdout.decode("gbk", errors="ignore")
        found = re.findall(r"IPv4[^:：\r\n]*[:：]\s*(\d{1,3}(?:\.\d{1,3}){3})", text, re.I)
        if not found:
            found = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
        for ip in found:
            add(ip)
    except Exception:
        pass
    try:
        add(get_local_ip())
    except Exception:
        pass
    return ips


def _bcast_of(ip, mask):
    """由 IP + 掩码算出该子网的定向广播地址，如 192.168.1.77/255.255.255.0 → 192.168.1.255"""
    try:
        i = struct.unpack("!I", socket.inet_aton(ip))[0]
        m = struct.unpack("!I", socket.inet_aton(mask))[0]
        return socket.inet_ntoa(struct.pack("!I", (i & m) | (~m & 0xFFFFFFFF)))
    except Exception:
        return ip.rsplit(".", 1)[0] + ".255"


def _ip_key(v):
    """IP 自然排序：192.168.1.9 < 192.168.1.10（按每段数值比，不是字符串）。
    容错：前后空白/不可见字符、结尾端口或掩码（192.168.1.8:80、192.168.1.0/24）。"""
    s = str(v or "")
    s = "".join(ch for ch in s if ch.isprintable()).strip()
    s = re.sub(r"[:/].*$", "", s).strip()
    parts = s.split(".")
    if len(parts) == 4:
        try:
            nums = tuple(int(p) for p in parts)
        except ValueError:
            nums = None
        if nums is not None and all(0 <= n <= 255 for n in nums):
            return (0, nums, "")
    return (1, (999, 999, 999, 999), s)


def _col_sort_key(col, rec):
    v = rec.get(col, "")
    if col == "ip" or "IP" in str(col):
        return _ip_key(v)
    if col == "mac":
        s = str(v or "").replace("-", ":").upper()
        return (s in ("", "-", "N/A"), s)
    if col == "no":
        return _ip_key(rec.get("ip"))
    s = str(v or "")
    return (s in ("", "-", "N/A"), s.lower())


def get_local_nets():
    """枚举本机每个 IPv4 网卡（IP、掩码、定向广播地址、网卡名）。
    只发 255.255.255.255 时，Windows 只会从默认路由那张网卡发出去，
    多网卡/多网段场景下别的网段一台都收不到 —— 必须逐网卡发定向广播。"""
    nets, seen = [], set()
    try:
        out = subprocess.run(["ipconfig"], capture_output=True,
                             creationflags=CREATE_NO_WINDOW, timeout=8)
        text = out.stdout.decode("gbk", errors="ignore")
    except Exception:
        text = ""
    cur = None
    cur_name = ""
    ADAPTER = re.compile(
        r"^\s*(?:以太网适配器|无线局域网适配器|隧道适配器|未知适配器|"
        r"Ethernet adapter|Wireless LAN adapter|Tunnel adapter|"
        r"Unknown adapter)\s*(.+?)\s*[:：]?\s*$", re.I)
    for line in text.splitlines():
        m = ADAPTER.match(line)
        if m:
            cur_name = m.group(1).strip(" :：")
            cur = None
            continue
        m = re.search(r"IPv4[^:：]*[:：]\s*(\d{1,3}(?:\.\d{1,3}){3})", line, re.I)
        if m:
            cur = m.group(1)
            continue
        m = re.search(r"(?:Subnet\s*Mask|子网掩码|掩码)[^:：]*[:：]"
                      r"\s*(\d{1,3}(?:\.\d{1,3}){3})", line, re.I)
        if m and cur:
            ip, mask = cur, m.group(1)
            cur = None
            if ip.startswith(("127.", "0.", "169.254.", "255.")) or ip in seen:
                continue
            seen.add(ip)
            nets.append({"ip": ip, "mask": mask, "bcast": _bcast_of(ip, mask),
                         "name": cur_name or "网卡"})
    for ip in get_local_ips():          # 兜底：解析不到掩码的按 /24 处理
        if ip not in seen:
            seen.add(ip)
            nets.append({"ip": ip, "mask": "255.255.255.0",
                         "bcast": _bcast_of(ip, "255.255.255.0"),
                         "name": "网卡"})
    return nets


def make_probe_sockets(group, port, probe=None, ifaces=None, listen=True):
    """按网卡分别加入组播组并发送探测报文。
    Windows 下 IP_ADD_MEMBERSHIP 用 INADDR_ANY 只会绑定默认网卡，
    因此必须逐个网卡地址加入组播，否则多网卡/跨网段场景收不到设备应答。
    ifaces=None 表示用全部网卡；传 IP 列表则只在这些网卡上收发。"""
    all_nets = get_local_nets()
    if ifaces:
        by_ip = {n["ip"]: n for n in all_nets}
        ips = [i for i in ifaces if i]
        nets = [by_ip.get(ip) or {"ip": ip, "mask": "255.255.255.0",
                                  "bcast": _bcast_of(ip, "255.255.255.0"),
                                  "name": "网卡"} for ip in ips]
    else:
        ips = [n["ip"] for n in all_nets]
        nets = all_nets
    if not ips:
        ips = get_local_ips()
        nets = [{"ip": i, "mask": "255.255.255.0",
                 "bcast": _bcast_of(i, "255.255.255.0"), "name": "网卡"}
                for i in ips]
    socks = []
    if listen:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", port))
            joined = 0
            for ip in ips:
                try:
                    s.setsockopt(
                        socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        struct.pack("4s4s", socket.inet_aton(group),
                                    socket.inet_aton(ip)))
                    joined += 1
                except OSError:
                    continue
            if joined == 0:
                try:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                 struct.pack("4s4s", socket.inet_aton(group),
                                             socket.inet_aton("0.0.0.0")))
                except OSError:
                    pass
            socks.append(s)
        except OSError:
            pass

    for net in nets:
        ip = net["ip"]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((ip, 0))
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                             socket.inet_aton(ip))
            except OSError:
                pass
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            if probe:
                for dst in ((group, port), ("255.255.255.255", port),
                            (net["bcast"], port)):
                    try:
                        s.sendto(probe, dst)
                    except OSError:
                        pass
            socks.append(s)
        except OSError:
            continue
    return socks


def onvif_discover(timeout=3.0, ifaces=None):
    """ONVIF WS-Discovery 组播探测，返回 {ip: {vendor, model, xaddr, kind}}"""
    import uuid as _uuid
    result = {}
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header>'
        f'<w:MessageID>uuid:{_uuid.uuid4()}</w:MessageID>'
        '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action e:mustUnderstand="true">'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>'
        '</d:Probe></e:Body></e:Envelope>'
    ).encode()
    socks = make_probe_sockets("239.255.255.250", 3702, probe,
                               ifaces=ifaces, listen=True)
    deadline = time.time() + timeout
    try:
        while socks and time.time() < deadline:
            r, _, _ = select.select(socks, [], [], 0.4)
            for s in r:
                try:
                    data, addr = s.recvfrom(65535)
                except Exception:
                    continue
                text = data.decode("utf-8", errors="ignore")
                if "ProbeMatch" not in text:
                    continue
                ip = addr[0]
                low = text.lower()
                model = ""
                m = re.search(r"onvif://www\.onvif\.org/hardware/([^<\s\"']+)", text)
                if m:
                    model = m.group(1)
                else:
                    m = re.search(r"onvif://www\.onvif\.org/name/([^<\s\"']+)", text)
                    if m:
                        model = m.group(1)
                xaddr = ""
                m = re.search(r"<[^>]*XAddrs[^>]*>([^<]+)<", text, re.I)
                if m:
                    xaddr = m.group(1).strip().split()[0]
                vendor = ""
                if "hikvision" in low or model.upper().startswith("DS-"):
                    vendor = "海康威视"
                elif "dahua" in low or model.upper().startswith("DH-"):
                    vendor = "大华"
                result[ip] = {
                    "source": "ONVIF",
                    "vendor": vendor, "model": model, "xaddr": xaddr,
                    "kind": "nvr" if ("networkvideostorage" in low
                                      or "recorder" in low) else "camera",
                }
    except Exception:
        pass
    finally:
        for s in socks:
            s.close()
    return result


def _xml_fields(text):
    """把 XML 报文拍平成 {小写tag: 文本}"""
    import xml.etree.ElementTree as ET
    d = {}
    try:
        root = ET.fromstring(text.strip())
        for el in root.iter():
            d[el.tag.lower()] = (el.text or "").strip()
    except Exception:
        pass
    return d


def _model_is_nvr(model, channels=None, disks=None):
    """根据型号/通道数/盘数判断是否录像机"""
    m = (model or "").upper()
    if re.search(r"NVR|DVR|XVR|混合|HCVR|EVR|HSR", m):
        return True
    # 海康录像机型号系列：DS-71/72/73/76/77/78/79/81/86/88/96xx
    if re.match(r"DS-(7[1-9]\d{2}|8[168]\d{2}|9\d{3})", m):
        return True
    try:
        if channels is not None and disks is not None \
                and int(channels) >= 4 and int(disks) >= 1:
            return True
    except (TypeError, ValueError):
        pass
    return False


def sadp_discover(timeout=8.0, ifaces=None):
    """海康 SADP/HiDiscover 组播发现（239.255.255.250:37020）。
    同一二层内无论设备 IP 属于哪个网段都会应答，
    可拿到型号/序列号/固件版本/是否激活，对标海康 SADP 工具。"""
    import uuid as _uuid
    results = {}
    probe = (f'<Probe><Uuid>{str(_uuid.uuid4()).upper()}</Uuid>'
             f'<Types>inquiry</Types></Probe>').encode()
    socks = make_probe_sockets("239.255.255.250", 37020, probe,
                               ifaces=ifaces)
    deadline = time.time() + timeout
    try:
        while socks and time.time() < deadline:
            r, _, _ = select.select(socks, [], [], 0.4)
            for s in r:
                try:
                    data, addr = s.recvfrom(65535)
                except Exception:
                    continue
                if b"ProbeMatch" not in data:
                    continue
                f = _xml_fields(data.decode("utf-8", errors="ignore"))
                if "ipv4address" not in f:
                    continue
                ip = f["ipv4address"] or addr[0]
                model = f.get("devicedescription", "")
                results[ip] = {
                    "source": "SADP",
                    "vendor": "海康威视",
                    "model": model,
                    "version": f.get("softwareversion", ""),
                    "serial": f.get("devicesn", ""),
                    "init": ("已初始化" if f.get("activated", "true").lower()
                             in ("true", "1") else "未初始化"),
                    "dtype": ("nvr" if _model_is_nvr(
                        model, f.get("digitalchannelnum"),
                        f.get("disknumber")) else "camera"),
                    "http_port": f.get("httpport", ""),
                    "serial_ip": addr[0],
                }
    except Exception:
        pass
    finally:
        for s in socks:
            s.close()
    return results


def _decode_hb(data):
    """心跳报文解码：去掉 \x00，必要时按 UTF-16LE 解（部分固件字段是宽字符）"""
    text = data.decode("utf-8", errors="ignore")
    if text.count("\x00") > len(text) * 0.25:
        try:
            wide = data.decode("utf-16-le", errors="ignore")
            if wide.count("\x00") < text.count("\x00"):
                text = wide
        except Exception:
            pass
    return text.replace("\x00", "")


def dahua_heartbeat_listen(timeout=6.0, stop_event=None, on_device=None,
                           stats=None, ifaces=None):
    """大华设备心跳监听（组播 239.255.255.250:30000，约 30 秒一轮）。
    报文为私有二进制，但型号/版本以 ASCII 串存在，可正则提取。
    timeout=None 时持续监听，直到 stop_event 置位。
    stats 传入 dict 可回传收到/解析成功的报文数，便于诊断。"""
    results = {}
    if stats is None:
        stats = {}
    stats.setdefault("packets", 0)
    stats.setdefault("matched", 0)
    socks = make_probe_sockets("239.255.255.250", 30000, None,
                               ifaces=ifaces, listen=True)
    if not socks:
        stats["error"] = "无法绑定 30000 端口"
        return results
    deadline = None if timeout is None else time.time() + timeout
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            if deadline is not None and time.time() >= deadline:
                break
            try:
                r, _, _ = select.select(socks, [], [], 0.5)
            except Exception:
                break
            for s in r:
                try:
                    data, addr = s.recvfrom(65535)
                except Exception:
                    continue
                stats["packets"] += 1
                text = _decode_hb(data)
                # 大华型号：DH-IPC-HDBW3441R-ZS / IPC-HFW2431T-AS / NVR5216-16P-4KS2E
                m = re.search(
                    r"\b((?:DH-)?IPC-[A-Z0-9][A-Z0-9\-]{3,}"
                    r"|(?:DH-|DHI-)?(?:NVR|DVR|XVR|HCVR|EVR|HSR)[A-Z0-9\-]{2,})",
                    text)
                v = re.search(r"\b(V\d+\.\d{2,3}\.\d{3,}[\w.]*)", text)
                sn = re.search(r"\b([0-9A-Z]{16,24})\b", text)
                if not (m or v):
                    continue
                stats["matched"] += 1
                model = m.group(1) if m else ""
                # 二进制报文里型号后常紧跟 8 位生产日期，去掉
                model = re.sub(r"(19|20)\d{6}$", "", model)
                dev = {
                    "source": "大华心跳",
                    "vendor": "大华",
                    "model": model,
                    "version": v.group(1) if v else "",
                    "serial": sn.group(1) if sn else "",
                    "init": "",
                    "dtype": ("nvr" if _model_is_nvr(model) else "camera"),
                }
                if addr[0] not in results:
                    results[addr[0]] = dev
                    if on_device:
                        try:
                            on_device(addr[0], dev)
                        except Exception:
                            pass
    except Exception:
        pass
    finally:
        for s in socks:
            s.close()
    return results


def _parse_dahua_packet(data, addr):
    """解析大华 v1(0xb3 老协议) / v2(DHIP+DHDiscover 新协议) 应答"""
    try:
        # v2：32 字节 DHIP 头，magic 在偏移 4
        if len(data) >= 36 and data[4:8] == b"DHIP" and \
                struct.unpack("<I", data[0:4])[0] == 32:
            pkt_len = struct.unpack("<I", data[16:20])[0]
            body = data[32:32 + pkt_len]
            j = json.loads(body.decode("utf-8", errors="ignore"))
            if j.get("method") != "client.notifyDevInfo":
                return None
            prm = j.get("params") or {}
            model = (prm.get("DeviceType") or "").strip()
            ip4 = ((prm.get("IPv4Address") or {}).get("IPAddress") or "").strip()
            mac = (prm.get("mac") or "").strip()
            serial = (prm.get("SerialNo") or mac or "").strip()
            return {
                "source": "ConfigTool协议", "vendor": "大华",
                "model": model or "大华设备",
                "version": "", "serial": serial, "mac": mac or "-",
                "init": "",
                "dtype": "nvr" if _model_is_nvr(model) else "camera",
                "ip": ip4 or addr[0],
            }
        # v1：老协议，0xb3 开头，0x78 字节定长头
        if len(data) >= 0x78 and data[0] == 0xB3:
            model = data[0x28:0x38].split(b"\x00")[0].decode("utf-8", "ignore").strip()
            ip_int = struct.unpack("<I", data[0x38:0x3C])[0]
            ip = socket.inet_ntoa(struct.pack("<I", ip_int)) if ip_int else addr[0]
            s2len = data[2]
            s3len = struct.unpack("<H", data[0x14:0x16])[0]
            mac_len = min(17, s2len)
            mac = data[0x78:0x78 + mac_len].decode("ascii", "ignore").strip("\x00 ")
            serial = ""
            if s2len > 17 and len(data) >= 0x78 + s2len:
                t2 = data[0x78 + 17:0x78 + s2len].decode("utf-8", "ignore")
                t2 = t2.replace("\x00", "").strip()
                if t2:
                    model = t2
            if s3len and len(data) >= 0x78 + s2len + s3len:
                s3 = data[0x78 + s2len:0x78 + s2len + s3len]
                for line in s3.decode("utf-8", "ignore").splitlines():
                    if line.lower().startswith("serialno:"):
                        serial = line.split(":", 1)[1].strip()
            if not model:
                return None
            return {
                "source": "Dahua广播v1", "vendor": "大华",
                "model": model, "version": "", "serial": serial,
                "mac": mac or "-", "init": "",
                "dtype": "nvr" if _model_is_nvr(model) else "camera",
                "ip": ip,
            }
    except Exception:
        return None
    return None


def _parse_dahua_hb(data, addr):
    """解析设备主动上报的心跳/通告（30000 端口的二进制文本）"""
    try:
        text = _decode_hb(data)
        m = re.search(
            r"\b((?:DH-)?IPC-[A-Z0-9][A-Z0-9\-]{3,}"
            r"|(?:DH-|DHI-)?(?:NVR|DVR|XVR|HCVR|EVR|HSR|TPC)[A-Z0-9\-]{2,})",
            text)
        v = re.search(r"\b(V\d+\.\d{2,3}\.\d{3,}[\w.]*)", text)
        if not (m or v):
            return None
        model = m.group(1) if m else ""
        model = re.sub(r"(19|20)\d{6}$", "", model)
        return {"source": "设备心跳", "vendor": "大华", "model": model or "大华设备",
                "version": v.group(1) if v else "", "serial": "",
                "mac": "-", "init": "",
                "dtype": "nvr" if _model_is_nvr(model) else "camera",
                "ip": addr[0]}
    except Exception:
        return None


def dahua_search(timeout=None, stop_event=None, on_device=None, stats=None,
                 targets=None, ifaces=None, unicast_only=False):
    """大华主动搜索（对标 ConfigTool）：
    v1：UDP 5050 广播（老固件）；v2：UDP 37810 组播239.255.255.251+广播（新固件）。
    每 2 秒重发探测；timeout=None 时自适应停止 —— 连续 8 秒没有新设备自动结束。
    targets 里的 IP 会额外做单播探测（跨网段/跨路由时唯一有效的办法）。
    返回 {ip: dev}"""
    results = {}
    if stats is None:
        stats = {}
    stats.setdefault("packets", 0)
    stats.setdefault("matched", 0)
    targets = [t for t in (targets or []) if t]
    v1_port, v2_port = 5050, 37810
    v2_group = "239.255.255.251"
    all_nets = get_local_nets()
    if ifaces:                          # 用户指定了网卡 → 只用它们
        by_ip = {n["ip"]: n for n in all_nets}
        nets = [by_ip.get(ip) or {"ip": ip, "mask": "255.255.255.0",
                                  "bcast": _bcast_of(ip, "255.255.255.0"),
                                  "name": "网卡"} for ip in ifaces]
    else:
        nets = all_nets
    iface_ips = [n["ip"] for n in nets]

    socks = []
    # v2 组播监听（逐网卡加入组播组）
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", v2_port))
        for ip in iface_ips:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                             struct.pack("4s4s", socket.inet_aton(v2_group),
                                         socket.inet_aton(ip)))
            except OSError:
                pass
        socks.append(s)
    except OSError:
        pass
    # v1 监听
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", v1_port))
        socks.append(s)
    except OSError:
        # 5050 常被 Windows「连接设备平台服务(CDPSvc)」独占：
        # 此时只能靠设备把应答回给我们的源端口，回固定 5050 的老固件会漏
        stats["no5050"] = True
    # 逐网卡发送套接字（带上该网卡的定向广播地址）
    senders = []
    # 单播专用：不绑定具体网卡，交给路由表选出口（跨网段/走 VPN 时才正确）
    uni_sock = None
    if targets:
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            u.bind(("", 0))
            uni_sock = u
            socks.append(u)
        except OSError:
            uni_sock = None
    for net in nets:
        ip = net["ip"]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((ip, 0))
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                             socket.inet_aton(ip))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            except OSError:
                pass
            senders.append((s, net["bcast"]))
            socks.append(s)
        except OSError:
            continue

    v1_req = bytes([
        0xa3, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ])
    v2_body = b'{"method":"DHDiscover.search","params":{"mac":"","uni":0}}\n'
    # DHIP 头 32 字节：magic=32 + 'DHIP' + u0 + u0 + bodyLen + u0 + u0 + u0
    # bodyLen 必须落在偏移 16（与设备应答一致），否则设备不认这条请求
    v2_req = (struct.pack("<I", 32) + b"DHIP" +
              struct.pack("<IIIIII", 0, 0, len(v2_body), 0, 0, 0) +
              v2_body)

    def send_probes():
        if not unicast_only:      # 单播探测模式：不发广播/组播，只问 targets
            for s, bcast in senders:
                for dst in ((bcast, v1_port), ("255.255.255.255", v1_port)):
                    try:
                        s.sendto(v1_req, dst)
                    except OSError:
                        pass
                for dst in ((v2_group, v2_port), (bcast, v2_port),
                            ("255.255.255.255", v2_port)):
                    try:
                        s.sendto(v2_req, dst)
                    except OSError:
                        pass
        # 指定 IP：单播直投（跨路由时广播到不了，只有单播能过去）
        if targets and uni_sock is not None:
            for ip in targets:
                for pkt, port in ((v1_req, v1_port), (v2_req, v2_port)):
                    try:
                        uni_sock.sendto(pkt, (ip, port))
                    except OSError:
                        pass

    send_probes()
    start_t = time.time()
    last_send = start_t
    last_new = start_t          # 最近一次发现"新设备"的时间
    # timeout=None → 自适应（像 ConfigTool）：先保证跑够 MIN_RUN，
    # 之后连续 IDLE_STOP 秒没有新设备就自动结束；硬上限 MAX_RUN 防止卡死
    MIN_RUN, IDLE_STOP, MAX_RUN = 12.0, 8.0, 180.0
    if timeout:
        hard_deadline = start_t + timeout
    else:
        hard_deadline = start_t + MAX_RUN
    try:
        while True:
            now = time.time()
            if stop_event is not None and stop_event.is_set():
                break
            if now >= hard_deadline:
                break
            if (timeout is None and now - start_t >= MIN_RUN
                    and now - last_new >= IDLE_STOP):
                break
            if now - last_send >= 2.0:
                send_probes()
                last_send = now
            try:
                r, _, _ = select.select(socks, [], [], 0.4)
            except Exception:
                break
            for s in r:
                try:
                    data, addr = s.recvfrom(65535)
                except Exception:
                    continue
                stats["packets"] += 1
                dev = _parse_dahua_packet(data, addr)
                if not dev:
                    continue
                stats["matched"] += 1
                ip = dev["ip"]
                if ip in results:
                    # 用信息更全的应答补齐
                    for k, v in dev.items():
                        if v not in ("", None, "-") and not results[ip].get(k):
                            results[ip][k] = v
                    continue
                results[ip] = dev
                last_new = time.time()
                if on_device:
                    try:
                        on_device(ip, dev)
                    except Exception:
                        pass
    except Exception:
        pass
    finally:
        for s in socks:
            s.close()
    return results


def broadcast_discover(timeout=6.0, ifaces=None):
    """并行执行 SADP / ONVIF / 大华心跳 三路组播发现并合并。
    ifaces 指定只用哪些网卡（None=全部）。
    返回 {ip: {vendor, model, version, serial, init, dtype, source}}"""
    merged = {}
    lock = threading.Lock()

    def merge(src):
        with lock:
            for ip, d in src.items():
                cur = merged.setdefault(ip, {})
                for k, v in d.items():
                    if v not in ("", None) and not cur.get(k):
                        cur[k] = v

    t1 = threading.Thread(
        target=lambda: merge(sadp_discover(max(4.0, timeout), ifaces=ifaces)),
        daemon=True)
    t2 = threading.Thread(
        target=lambda: merge(onvif_discover(max(3.0, timeout - 2), ifaces=ifaces)),
        daemon=True)
    t3 = threading.Thread(
        target=lambda: merge(dahua_heartbeat_listen(timeout, ifaces=ifaces)),
        daemon=True)
    for t in (t1, t2, t3):
        t.start()
    for t in (t1, t2, t3):
        t.join()
    return merged


def oui_vendor(mac):
    if not mac:
        return ""
    prefix = mac[:8].upper()
    if prefix in OUI_HIK:
        return "海康威视"
    if prefix in OUI_DAHUA:
        return "大华"
    if prefix in OUI_OTHER:
        return OUI_OTHER[prefix]
    # 第二字节最低位为 1 表示本地管理地址，通常是手机/终端的随机 MAC
    try:
        if int(mac[:2], 16) & 0x02:
            return "随机MAC(手机/终端)"
    except Exception:
        pass
    return ""


def classify(ip, mac, ports, banners):
    """根据 OUI / 开放端口 / 指纹给出厂商与设备类型（严格指纹，避免误判）"""
    fp = " ".join(banners.values()).lower()
    ov = oui_vendor(mac)
    vendor, note = "", ""

    # 海康：仅认可靠的固件特征，不要用 "isapi" 之类的路径回显
    hik = any(k in fp for k in (
        "hikvision", "dvrdvs", "substatuscode", 'realm="ip camera"',
        "ds-2cd", "ds-2de", "ds-76", "ds-78", "ds-96"))
    dah = any(k in fp for k in (
        "dahua", "dh-ipc", "dh-nvr", "dh-sd", "dahua rtsp"))

    if hik:
        vendor = "海康威视"
    elif dah:
        vendor = "大华"
    elif ov == "海康威视":
        vendor, note = "海康威视", "(MAC疑似)"
    elif ov == "大华":
        vendor, note = "大华", "(MAC疑似)"
    elif 37777 in ports:
        vendor, note = "大华系", "(端口疑似)"
    elif 34567 in ports:
        vendor, note = "私有协议设备", "(疑似DVR/摄像机)"
    elif ov:
        vendor = ov

    # 视频类判定：必须有 RTSP / 大华私有端口 / 明确的品牌指纹
    is_video = (hik or dah or 554 in ports or 37777 in ports or 34567 in ports
                or (8000 in ports and ov == "海康威视"))
    # 录像机（NVR/DVR）特征：页面/固件里带 nvr、dvr、硬盘录像等字样
    nvr_kw = any(k in fp for k in (
        "nvr", "dvr", "network video recorder", "digital video recorder",
        "硬盘录像", "录像机", "network_video_storage"))
    if nvr_kw and (is_video or 80 in ports or 8000 in ports or 37777 in ports):
        is_video = True
        dtype = "录像机(NVR/DVR)"
    elif is_video:
        dtype = "摄像机/录像机(RTSP)" if 554 in ports else "视频监控设备"
    elif 8000 in ports and not any(
            k in fp for k in ("microsoft-iis", "nginx", "apache", "lexmark")):
        # 只开 8000（媒体/SDK 口）且网页不像通用 Web 服务，多半是监控类设备
        dtype = "疑似监控设备(开放8000)"
    elif any(p in ports for p in (80, 8080, 443, 8000)):
        dtype = "网络设备/主机"
    else:
        dtype = "未知设备"
    return vendor + note, dtype


def short_banner(banners):
    """把指纹压缩成一行可读信息"""
    parts = []
    for key in ("rtsp", "http", "https", "isapi", "rpc2"):
        b = banners.get(key, "")
        if not b:
            continue
        m = re.search(r"Server:\s*([^\r\n]+)", b, re.I)
        if m:
            parts.append(m.group(1).strip()[:28])
        m = re.search(r"<title>([^<]*)</title>", b, re.I)
        if m:
            parts.append(m.group(1).strip()[:24])
        if not m:
            m = re.search(r'Digest realm="([^"]+)"', b, re.I)
            if m:
                parts.append("需认证:" + m.group(1).strip()[:20])
        m = re.search(r"HTTP/1\.[01]\s+(\d{3})", b)
        if m and not parts:
            parts.append(f"HTTP {m.group(1)}")
    txt = " / ".join(dict.fromkeys(parts))
    return txt[:60]


class Tooltip:
    """简易悬浮提示"""

    def __init__(self, widget):
        self.widget = widget
        self.tip = None

    def show(self, text, event):
        self.hide()
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        # 深色小字提示框，93% 不透明度，尽量少挡住格子
        tk.Label(
            self.tip, text=text, justify="left", background="#2B2F36",
            fg="#E8EAED", font=("Microsoft YaHei", 8), padx=8, pady=4,
        ).pack()
        try:
            self.tip.attributes("-alpha", 0.93)
        except Exception:
            pass
        self.tip.update_idletasks()
        w, h = self.tip.winfo_width(), self.tip.winfo_height()
        # 默认显示在鼠标上方，不挡下方格子；贴顶时改到下方，贴右时往左收
        x = event.x_root + 14
        y = event.y_root - h - 10
        if y < 36:
            y = event.y_root + 16
        if x + w > self.tip.winfo_screenwidth() - 10:
            x = event.x_root - w - 14
        self.tip.wm_geometry(f"+{x}+{y}")

    def hide(self):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class LongPingWindow:
    """长 ping（持续 ping）窗口"""

    def __init__(self, master, ip):
        self.ip = ip
        self.proc = None
        self.running = False
        self.sent = self.recv = self.lost = 0

        self.win = tk.Toplevel(master)
        self.win.title(f"长Ping - {ip}")
        self.win.geometry("660x440")
        self.win.minsize(420, 260)
        self.win.protocol("WM_DELETE_WINDOW", self.on_close)

        top = ttk.Frame(self.win, padding=6)
        top.pack(fill="x")
        self.btn_toggle = ttk.Button(top, text="停止", command=self.toggle)
        self.btn_toggle.pack(side="left")
        ttk.Button(top, text="保存记录", command=self.save_log).pack(side="left", padx=6)
        self.lbl_stat = ttk.Label(top, text="已发 0 / 收到 0 / 丢失 0 (0.0%)")
        self.lbl_stat.pack(side="right")

        self.txt = tk.Text(self.win, font=("Consolas", 10), state="disabled",
                           bg="#1E1E1E", fg="#D4D4D4", wrap="none")
        self.txt.pack(fill="both", expand=True, padx=6, pady=(0, 2))
        ttk.Sizegrip(self.win).pack(side="right", anchor="se", padx=2, pady=1)
        self.win.after(150, self.start)

    def toggle(self):
        if self.running:
            self.stop()
            self.log("—— 已手动停止 ——", "#FFA500")
        else:
            self.start()

    def start(self):
        if self.running:
            return
        self.running = True
        self.btn_toggle.config(text="停止")
        self.proc = subprocess.Popen(
            ["ping", "-t", self.ip], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW,
        )
        threading.Thread(target=self.reader, daemon=True).start()

    def reader(self):
        proc = self.proc
        try:
            for raw in iter(proc.stdout.readline, b""):
                line = raw.decode("gbk", errors="ignore").strip()
                if not line:
                    continue
                ts = time.strftime("%H:%M:%S")
                low = line.lower()
                if "ttl=" in low:
                    self.sent += 1
                    self.recv += 1
                    m = re.search(r"[=<]\s*(\d+)\s*ms", line)
                    lat = m.group(1) + "ms" if m else "-"
                    self.win.after(0, self.log,
                                   f"[{ts}] 回复  时间={lat:>6}  {line}", "#4EC94E")
                elif "超时" in line or "timed out" in low or "无法访问" in line \
                        or "unreachable" in low:
                    self.sent += 1
                    self.lost += 1
                    self.win.after(0, self.log, f"[{ts}] {line}", "#FF6B6B")
                elif "中断" in line or "abort" in low:
                    self.win.after(0, self.log, f"[{ts}] {line}", "#FFA500")
                else:
                    self.win.after(0, self.log, f"[{ts}] {line}", "#9CDCFE")
                self.win.after(0, self.update_stat)
        except Exception:
            pass
        finally:
            self.win.after(0, self._stopped)

    def _stopped(self):
        self.running = False
        self.btn_toggle.config(text="开始")

    def update_stat(self):
        total = self.recv + self.lost
        pct = (self.lost / total * 100) if total else 0.0
        self.lbl_stat.config(
            text=f"已发 {self.sent} / 收到 {self.recv} / 丢失 {self.lost} ({pct:.1f}%)"
        )

    def log(self, text, color=None):
        self.txt.config(state="normal")
        if color:
            tag = "c" + color[1:]
            self.txt.tag_configure(tag, foreground=color)
            self.txt.insert("end", text + "\n", tag)
        else:
            self.txt.insert("end", text + "\n")
        self.txt.see("end")
        self.txt.config(state="disabled")

    def save_log(self):
        path = filedialog.asksaveasfilename(
            title="保存长Ping记录", defaultextension=".txt",
            initialfile=f"长Ping_{self.ip.replace('.', '_')}.txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.txt.get("1.0", "end"))
            messagebox.showinfo("提示", "记录已保存", parent=self.win)
        except Exception as e:
            messagebox.showerror("错误", f"保存失败：{e}", parent=self.win)

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass
            self.proc = None

    def on_close(self):
        self.stop()
        self.win.destroy()


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.gen = 0
        self.scanning = False
        self.results = {}           # octet -> (online, latency, ts)
        self.cells = []
        self.base = "192.168.0"
        self._font_size = 9
        self._resize_job = None
        self._pending_size = None

        # 设备发现在跑的状态
        self.dev_scanning = False
        self.dev_gen = 0
        self.devices = []           # [{ip, mac, vendor, dtype, ports, banner}]
        self._sort_state = {         # {页签: {col, desc, user}} 表头点击排序状态
            "dev": {"col": "ip", "desc": False},     # 默认就按 IP 数值升序
            "hik": {"col": "ip", "desc": False},
            "dahua": {"col": "ip", "desc": False},
        }
        self._hik_rows = []         # 海康页待插入队列（逐行出现）
        self._passive_seen = {}     # 常驻监听去重 {ip: 时间}
        self._history = load_history()
        self._nets = get_local_nets()   # [{ip, mask, bcast, name}]
        self.hik_ifaces = None          # 本次海康搜索使用的网卡
        self._tip_labels = []           # 底部说明文字（随窗口宽度自动换行）

        root.title("网络工具")
        root.geometry("880x700")
        root.minsize(720, 620)
        root.resizable(True, True)
        root.configure(bg="#F4F5F7")

        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            pass
        base_font = ("Microsoft YaHei", 9)
        style.configure(".", font=base_font)
        style.configure("Treeview", rowheight=24, font=base_font,
                        background="#FFFFFF", fieldbackground="#FFFFFF")
        style.configure("Treeview.Heading", font=("Microsoft YaHei", 9, "bold"))
        style.configure("TNotebook", background="#F4F5F7", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 6), font=base_font)
        style.configure("TFrame", background="#F4F5F7")
        style.configure("TButton", font=base_font, padding=(10, 3))
        style.configure("TLabel", font=base_font, background="#F4F5F7")
        style.configure("TEntry", font=base_font)
        style.configure("TProgressbar", thickness=6)

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_ping = ttk.Frame(self.nb)
        self.tab_dev = ttk.Frame(self.nb)
        self.tab_hik = ttk.Frame(self.nb)
        self.tab_dahua = ttk.Frame(self.nb)
        self.nb.add(self.tab_ping, text="  批量Ping  ")
        self.nb.add(self.tab_dev, text="  设备发现  ")
        self.nb.add(self.tab_hik, text="  海康设备(SADP)  ")
        self.nb.add(self.tab_dahua, text="  大华设备  ")

        self._build_ping_tab()
        self._build_dev_tab()
        self._build_hik_tab()
        self._build_dahua_tab()
        # 建完表先按 IP 数值排一次（历史记录也一起排好）
        for w in ("dev", "hik", "dahua"):
            try:
                self._apply_sort(w)
            except Exception:
                pass

        bar = ttk.Frame(root)
        bar.pack(fill="x", side="bottom")
        ttk.Sizegrip(bar).pack(side="right", padx=(0, 2))
        ttk.Button(bar, text="关于", width=4,
                   command=self.show_about).pack(side="left", padx=(6, 4), pady=2)
        self.status = ttk.Label(
            bar, text="就绪",
            padding=(10, 4), relief="sunken", anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        ttk.Label(bar, text="网卡:").pack(side="right", pady=3)
        self.cb_iface = ttk.Combobox(bar, state="readonly", width=26,
                                     font=("Microsoft YaHei", 9))
        self.cb_iface.pack(side="right", padx=(4, 8), pady=3)
        self.cb_iface.bind("<<ComboboxSelected>>", self.on_iface_change)
        ttk.Button(bar, text="刷新", width=5,
                   command=self._load_ifaces).pack(side="right", padx=(4, 0))
        self._load_ifaces()

        root.bind("<Configure>", self._apply_tip_wrap)
        self.nb.bind("<<NotebookTabChanged>>", self._apply_tip_wrap)
        root.after(300, self._apply_tip_wrap)   # 初次布局后按实际宽度换行
        root.after(80, self.poll_queue)
        root.after(600, self._start_passive)

    # ==================== 关于 ====================
    APP_NAME = "网络工具"
    APP_VERSION = "v1.0"
    APP_AUTHOR = "ysl"
    APP_EMAIL = "328357351@qq.com"

    def show_about(self):
        messagebox.showinfo(
            "关于",
            f"{self.APP_NAME} {self.APP_VERSION}\n"
            f"批量Ping / 局域网设备发现（海康SADP、ONVIF、大华ConfigTool协议）\n\n"
            f"开发者：{self.APP_AUTHOR}\n"
            f"邮箱：{self.APP_EMAIL}\n"
            f"© 2026 {self.APP_AUTHOR}. 保留所有权利.")

    # ==================== 常驻监听（ConfigTool 同款）====================
    def _start_passive(self):
        self._passive_stop = threading.Event()
        ifaces = self.sel_ifaces() or [n["ip"] for n in self._nets]
        threading.Thread(target=self._passive_loop,
                         args=(self._passive_stop, ifaces), daemon=True).start()

    def _restart_passive(self):
        """切换网卡后重启常驻监听，让组播按新网卡加入"""
        if getattr(self, "_passive_stop", None):
            self._passive_stop.set()
        self._passive_seen.clear()
        self.root.after(400, self._start_passive)

    def _passive_loop(self, stop_evt=None, ifaces=None):
        """程序一启动就一直在听：设备主动上报/心跳/应答，随时收进来。
        ConfigTool 之所以"ping 不通也能搜到"，很大程度就是它常驻监听。"""
        socks = []
        ok_ports = []
        ifaces = ifaces or [n["ip"] for n in self._nets]

        def add(port, group=None):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", port))
                if group:
                    for ip in ifaces:
                        try:
                            s.setsockopt(
                                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                struct.pack("4s4s", socket.inet_aton(group),
                                            socket.inet_aton(ip)))
                        except OSError:
                            pass
                s.setblocking(False)
                socks.append(s)
                ok_ports.append(port)
            except OSError:
                pass

        add(37810, "239.255.255.251")    # 新固件 DHIP 通知
        add(5050)                        # 老固件上报
        add(30000, "239.255.255.250")    # 设备心跳
        if not socks:
            return
        self.q.put(("passive_info", list(ok_ports)))
        while not (stop_evt and stop_evt.is_set()):
            try:
                r, _, _ = select.select(socks, [], [], 1.5)
            except Exception:
                break
            if stop_evt and stop_evt.is_set():
                break
            for s in r:
                try:
                    data, addr = s.recvfrom(65535)
                except Exception:
                    continue
                dev = _parse_dahua_packet(data, addr)
                if not dev:
                    dev = _parse_dahua_hb(data, addr)   # 30000 心跳/主动上报
                if not dev:
                    continue
                ip = dev["ip"]
                now = time.time()
                if now - self._passive_seen.get(ip, 0) < 300:
                    continue          # 5 分钟内同一台不重复入表
                self._passive_seen[ip] = now
                dev["source"] = "被动监听"
                self.q.put(("dahua_add", ip, dev))
        for s in socks:
            try:
                s.close()
            except Exception:
                pass

    # ==================== 说明文字自动换行 ====================
    def _add_tip(self, tab, text, row):
        """页面底部的灰色说明文字：小字号、随窗口宽度自动换行、尽量省地方"""
        lbl = ttk.Label(tab, padding=(10, 1, 10, 2), foreground="#8A8F98",
                        font=("Microsoft YaHei", 8), text=text,
                        wraplength=820, justify="left")
        lbl.grid(row=row, column=0, sticky="ew")
        self._tip_labels.append(lbl)
        return lbl

    def _apply_tip_wrap(self, event=None):
        if event is not None and event.widget is not self.root:
            return                      # 只响应主窗口尺寸变化
        rw = self.root.winfo_width()
        for lbl in self._tip_labels:
            w = lbl.master.winfo_width()
            if w <= 80:                 # 页签还没显示过 → 按主窗口宽度估算
                w = rw - 40
            if w > 80:
                try:
                    lbl.config(wraplength=max(300, w - 28))
                except Exception:
                    pass

    # ==================== 网卡选择 ====================
    def _load_ifaces(self):
        """刷新网卡下拉框（多网卡/插拔网线后点“刷新网卡”）"""
        try:
            self._nets = get_local_nets()
        except Exception:
            self._nets = []
        items = ["全部网卡（自动）"]
        for n in self._nets:
            items.append(f"{n['ip']} · {n.get('name') or '网卡'}")
        try:
            self.cb_iface["values"] = items
            if self.cb_iface.get() not in items:
                self.cb_iface.current(0)
        except Exception:
            pass

    def sel_ifaces(self):
        """当前选中的网卡 IP 列表；None = 全部网卡（自动）"""
        try:
            txt = (self.cb_iface.get() or "").strip()
        except Exception:
            return None
        if not txt or txt.startswith("全部"):
            return None
        ip = txt.split("·")[0].strip()
        return [ip] if ip else None

    def iface_label(self, ip):
        for n in self._nets:
            if n["ip"] == ip:
                return f"{ip}({n.get('name') or '网卡'})"
        return ip

    def on_iface_change(self, event=None):
        ips = self.sel_ifaces()
        self._passive_seen.clear()
        self._restart_passive()
        self.status.config(
            text=f"已切换网卡：{ips[0] if ips else '全部网卡（自动）'}"
                 f" —— 常驻监听已重启，后续搜索都用这块网卡")

    def _history_nets(self):
        """历史记录里出现过、但本机网卡没覆盖的网段（最多 2 个 C 段）"""
        local = {n["ip"].rsplit(".", 1)[0] for n in self._nets}
        pre_list = []
        for key in ("dahua", "hik"):
            for r in self._history.get(key) or []:
                ip = (r or {}).get("ip") or ""
                if ip.count(".") != 3:
                    continue
                pre = ip.rsplit(".", 1)[0]
                if pre not in local and pre not in pre_list:
                    pre_list.append(pre)
        out = []
        for pre in pre_list[:2]:
            out += [f"{pre}.{i}" for i in range(1, 255)]
        return out

    # ==================== 批量Ping 页 ====================
    def _build_ping_tab(self):
        tab = self.tab_ping
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        top = ttk.Frame(tab, padding=(8, 8, 8, 4))
        top.grid(row=0, column=0, sticky="ew")
        ttk.Label(top, text="起始网段:").pack(side="left")
        self.entry = ttk.Entry(top, width=20, font=("Consolas", 11))
        self.entry.insert(0, "192.168.0.0")
        self.entry.pack(side="left", padx=6)
        self.entry.bind("<Return>", lambda e: self.start_scan())
        self.btn_scan = ttk.Button(top, text="批量Ping", command=self.start_scan)
        self.btn_scan.pack(side="left", padx=(0, 6))
        self.btn_export = ttk.Button(top, text="导出报表", command=self.export_report,
                                     state="disabled")
        self.btn_export.pack(side="left")

        # 网格容器：随窗口拉伸，单元格均分；浅色底 + 细分隔线
        holder = tk.Frame(tab, bg="#D9DBDF")
        holder.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.grid_holder = holder
        self.grid_frame = tk.Frame(holder, bg="#D9DBDF")
        self.grid_frame.pack(fill="both", expand=True, padx=1, pady=1)
        for r in range(16):
            self.grid_frame.rowconfigure(r, weight=1, uniform="cell")
            self.grid_frame.columnconfigure(r, weight=1, uniform="cell")

        for i in range(256):
            row, col = divmod(i, 16)
            cell = tk.Label(self.grid_frame, text=str(i), relief="flat", bd=0,
                            bg="#FFFFFF", fg="#8A8F98",
                            font=("Segoe UI", self._font_size, "bold"))
            cell.grid(row=row, column=col, sticky="nsew", padx=1, pady=1)
            tip = Tooltip(cell)
            cell.bind("<Enter>", lambda e, idx=i, t=tip: self.on_enter(e, idx, t))
            cell.bind("<Leave>", lambda e, t=tip: t.hide())
            cell.bind("<Button-1>", lambda e, idx=i: self.open_long_ping(idx))
            cell.bind("<Button-3>", lambda e, idx=i: self.cell_menu(e, idx))
            self.cells.append(cell)
        self.grid_frame.bind("<Configure>", self.on_grid_configure)

    def on_grid_configure(self, event):
        if event.width < 80 or event.height < 80:
            return
        self._pending_size = (event.width, event.height)
        if self._resize_job:
            self.root.after_cancel(self._resize_job)
        self._resize_job = self.root.after(120, self._apply_grid_font)

    def _apply_grid_font(self):
        self._resize_job = None
        if not self._pending_size:
            return
        w, h = self._pending_size
        cell = min(w, h) / 16.0
        # 字号随格子缩放，但限制在 6-9pt，接近参考工具的小数字风格
        size = int(cell * 0.24)
        size = max(6, min(9, size))
        if size != self._font_size:
            self._font_size = size
            f = ("Segoe UI", size, "bold")
            for c in self.cells:
                c.config(font=f)

    def parse_base(self):
        m = re.match(r"^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})", self.entry.get().strip())
        if not m:
            return None
        parts = [int(g) for g in m.groups()]
        if any(p > 255 for p in parts):
            return None
        return ".".join(str(p) for p in parts)

    def start_scan(self):
        base = self.parse_base()
        if not base:
            messagebox.showerror("错误", "请输入正确的网段，例如 192.168.0.0")
            return
        if self.scanning:
            return
        self.scanning = True
        self.gen += 1
        gen = self.gen
        self.base = base
        self.results.clear()
        self.btn_scan.config(state="disabled")
        self.btn_export.config(state="disabled")
        for i, cell in enumerate(self.cells):
            cell.config(bg="#FFFFFF", fg="#8A8F98", text=str(i))
        self.status.config(text=f"正在扫描 {base}.0 - {base}.255 ...")
        pool = ThreadPoolExecutor(max_workers=100)
        for i in range(256):
            pool.submit(self._ping_worker, i, f"{base}.{i}", gen)
        self._pool = pool

    def _ping_worker(self, idx, ip, gen):
        online, lat = ping_once(ip)
        self.q.put(("ping", gen, idx, ip, online, lat, time.strftime("%H:%M:%S")))

    def _hik_add_one(self, ip, dev, mac):
        new = {"model": dev.get("model") or "-",
               "serial": dev.get("serial") or "-",
               "version": dev.get("version") or "-",
               "init": dev.get("init") or "-",
               "http": dev.get("http_port") or "-",
               "mac": mac}
        exist = next((r for r in self.hik_records if r["ip"] == ip), None)
        if exist is not None:      # 命中上次记录 → 升级为在线
            changed = exist.pop("hist", None) is not None
            for k, v in new.items():
                if v not in ("", None, "-") and exist.get(k) in ("", None, "-"):
                    exist[k] = v
                    changed = True
            if changed:
                self._apply_sort("hik")
            return
        rec = dict(new, ip=ip)
        self.hik_records.append(rec)
        if self._can_append_tail("hik", rec):
            self._fill_hik_row(rec)        # 正好排末尾 → 直接追加，避免整表重绘闪烁
        elif self._sort_state.get("hik", {}).get("col"):
            self._apply_sort("hik")
        else:
            self._fill_hik_row(rec)
        self.lbl_hik.config(text=f"共 {len(self.hik_records)} 台")

    def _can_append_tail(self, which, rec):
        """当前按某列排序时，判断新记录是否正好排在有序列表的最后。
        是的话直接 append 一行即可，不必删表重插（设备多时整表重绘会闪）。"""
        st = self._sort_state.get(which) or {}
        col = st.get("col")
        if not col:
            return False
        recs = {"hik": self.hik_records, "dahua": self.dahua_records,
                "dev": self.devices}.get(which)
        if not recs or len(recs) < 2:
            return False
        key = _col_sort_key(col, rec)
        desc = bool(st.get("desc"))
        for r in recs[:-1]:
            k = _col_sort_key(col, r)
            if (k < key) if desc else (k > key):
                return False
        return True

    def _flush_hik_row(self):
        """每次 poll 只放一行，让设备像 ConfigTool 那样逐条出现"""
        if not self._hik_rows:
            return
        item = self._hik_rows.pop(0)
        if item[0] == "add":
            self._hik_add_one(item[1], item[2], item[3])
            return
        _, count = item
        self.hik_running = False
        self.btn_hik.config(state="normal")
        self.btn_hik_stop.config(state="disabled")
        self.hik_bar.stop()
        self._save_hist()
        self.status.config(
            text=f"海康设备搜索完成 — 共 {count} 台")

    def poll_queue(self):
        try:
            self._flush_hik_row()
            try:
                while True:
                    msg = self.q.get_nowait()
                    if msg[0] == "ping":
                        _, gen, idx, ip, online, lat, ts = msg
                        if gen != self.gen:
                            continue
                        self.results[idx] = (online, lat, ts)
                        self.cells[idx].config(
                            bg=COLOR_ONLINE if online else COLOR_OFFLINE, fg="white")
                    elif msg[0] == "dev_progress":
                        _, gen, text = msg
                        if gen == self.dev_gen:
                            self.status.config(text=text)
                    elif msg[0] == "dev_add":
                        _, gen, dev = msg
                        if gen == self.dev_gen:
                            self._add_device_row(dev)
                    elif msg[0] == "dev_done":
                        _, gen, count = msg
                        if gen == self.dev_gen:
                            self.dev_scanning = False
                            self.btn_dev.config(state="normal")
                            self.btn_dev_export.config(state="normal")
                            self.dev_bar.stop()
                            self.status.config(
                                text=f"设备发现完成 — 共发现 {count} 台设备")
                    elif msg[0] == "hik_add":
                        _, ip, dev, mac = msg
                        # 排队逐行出现（SADP 一轮会同时回十几台，一起插入会"一下全跳出来"）
                        self._hik_rows.append(("add", ip, dev, mac))
                    elif msg[0] == "hik_done":
                        _, count = msg
                        self._hik_rows.append(("done", count))
                    elif msg[0] == "passive_info":
                        if not (self.dahua_running or self.scanning
                                or self.dev_scanning or self.hik_running):
                            self.status.config(text="就绪")
                    elif msg[0] == "dahua_add":
                        _, ip, dev = msg
                        exist = next((r for r in self.dahua_records
                                      if r["ip"] == ip), None)
                        if exist is not None:
                            changed = exist.pop("hist", None) is not None
                            for k, v in dev.items():
                                if v not in ("", None, "-") and \
                                        exist.get(k) in ("", None, "-"):
                                    exist[k] = v
                                    changed = True
                            if changed:
                                if not exist.get("source") or exist["source"] == "上次记录":
                                    exist["source"] = dev.get("source") or "ConfigTool协议"
                                self._apply_sort("dahua")
                            continue
                        rec = {"ip": ip, "mac": dev.get("mac") or "-",
                               "model": dev.get("model") or "-",
                               "version": dev.get("version") or "-",
                               "serial": dev.get("serial") or "-",
                               "source": dev.get("source", "ConfigTool协议")}
                        self.dahua_records.append(rec)
                        if self._can_append_tail("dahua", rec):
                            self._fill_dahua_row(rec)
                        elif self._sort_state.get("dahua", {}).get("col"):
                            self._apply_sort("dahua")
                        else:
                            self._fill_dahua_row(rec)
                        self.lbl_dahua.config(text=f"共 {len(self.dahua_records)} 台")
                    elif msg[0] == "dahua_done":
                        _, n, pkts, matched, no5050 = msg
                        self.dahua_running = False
                        self.btn_dahua.config(state="normal")
                        self.btn_dahua_stop.config(state="disabled")
                        self.dahua_bar.stop()
                        if pkts == 0:
                            tip = ("未收到任何应答 — 本机防火墙可能拦了入站 UDP"
                                   "（5050/37810/30000），或设备关闭了发现/自动注册；"
                                   "可先用上面的起止 IP 扫描")
                        elif matched == 0:
                            tip = (f"收到 {pkts} 个 UDP 包但未识别 — "
                                   f"可能不是大华协议报文，请改用范围扫描")
                        else:
                            tip = f"收到 {pkts} 个应答包，识别 {n} 台"
                        if no5050 and not getattr(self, "dahua_unicast", False):
                            tip += ("；注意：UDP 5050 被系统服务(CDPSvc)占用，"
                                    "回固定 5050 的老固件可能漏发现")
                        self.status.config(
                            text=f"大华搜索结束 — {tip}")
                        self._save_hist()

                    elif msg[0] == "dahua_scan_done":
                        _, count = msg
                        self.dahua_running = False
                        self.btn_dahua.config(state="normal")
                        self.btn_dahua_scan.config(state="normal")
                        self.dahua_bar.stop()
                        self._save_hist()
                        self.status.config(
                            text=f"大华扫描完成 — 发现 {count} 台")
            except queue.Empty:
                pass

            if self.scanning:
                total = len(self.results)
                online_cnt = sum(1 for v in self.results.values() if v[0])
                self.status.config(
                    text=f"正在扫描 {self.base}.0 - {self.base}.255 ...  "
                         f"已响应 {total}/256，其中在线 {online_cnt} 台")
                if total >= 256:
                    self.scanning = False
                    self._pool.shutdown(wait=False)
                    self.btn_scan.config(state="normal")
                    self.btn_export.config(state="normal")
                    self.status.config(
                        text=f"扫描完成 — 在线 {online_cnt} 台 / 共 256 个地址")
        except Exception:
            pass          # 任何 UI 更新异常都不能让消息泵停摆
        finally:
            self.root.after(80, self.poll_queue)

    # ---------- 单元格交互 ----------
    def on_enter(self, event, idx, tip):
        ip = f"{self.base}.{idx}"
        r = self.results.get(idx)
        if r is None:
            text = f"IP: {ip}\n状态: 未扫描"
        else:
            online, lat, ts = r
            text = (f"IP: {ip}\n状态: {'在线' if online else '超时/不在线'}\n"
                    f"延迟: {lat if lat is not None else '-'} ms\n"
                    f"扫描时间: {ts}")
        tip.show(text, event)

    def open_long_ping(self, idx):
        LongPingWindow(self.root, f"{self.base}.{idx}")

    def copy_ip(self, idx):
        self.copy_text(f"{self.base}.{idx}")

    # ---------- 右键菜单 / 打开网页 ----------
    def copy_text(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.config(text=f"已复制: {text[:70]}")

    def open_web(self, ip, scheme="http", port=None):
        tail = f":{port}" if port else ""
        url = f"{scheme}://{ip}{tail}"
        try:
            webbrowser.open(url)
            self.status.config(text=f"已在浏览器打开 {url}")
        except Exception as e:
            self.status.config(text=f"打开 {url} 失败：{e}")

    def cell_menu(self, event, idx):
        ip = f"{self.base}.{idx}"
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=f"打开网页  http://{ip}",
                         command=lambda: self.open_web(ip, "http"))
        menu.add_command(label=f"打开网页  https://{ip}",
                         command=lambda: self.open_web(ip, "https"))
        menu.add_separator()
        menu.add_command(label="长Ping", command=lambda: LongPingWindow(self.root, ip))
        menu.add_command(label="复制IP", command=lambda: self.copy_text(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _dev_record(self, ip):
        return next((d for d in self.devices if d["ip"] == ip), None)

    def export_report(self):
        if not self.results:
            messagebox.showinfo("提示", "请先执行批量Ping")
            return
        path = filedialog.asksaveasfilename(
            title="导出报表", defaultextension=".csv",
            initialfile=f"Ping报表_{self.base.replace('.', '_')}"
                        f"_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            filetypes=[("CSV 文件", "*.csv")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["序号", "IP地址", "状态", "延迟(ms)", "扫描时间"])
                online_cnt = 0
                for i in range(256):
                    r = self.results.get(i)
                    ip = f"{self.base}.{i}"
                    if r is None:
                        w.writerow([i, ip, "未扫描", "", ""])
                    else:
                        online, lat, ts = r
                        online_cnt += 1 if online else 0
                        w.writerow([i, ip, "在线" if online else "不在线",
                                    lat if lat is not None else "", ts])
                w.writerow([])
                w.writerow(["汇总", f"网段 {self.base}.0/24",
                            f"在线 {online_cnt} 台 / 共 256 地址",
                            f"导出时间 {time.strftime('%Y-%m-%d %H:%M:%S')}", ""])
            messagebox.showinfo("提示", f"报表已导出:\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败：{e}")

    # ==================== 局域网设备页 ====================
    def _build_dev_tab(self):
        tab = self.tab_dev
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        bar = ttk.Frame(tab, padding=(8, 8, 8, 2))
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, text="起始IP:").pack(side="left")
        self.dev_start = ttk.Entry(bar, width=15, font=("Consolas", 10))
        self.dev_start.insert(0, "192.168.0.1")
        self.dev_start.pack(side="left", padx=(4, 8))
        ttk.Label(bar, text="结束IP:").pack(side="left")
        self.dev_end = ttk.Entry(bar, width=15, font=("Consolas", 10))
        self.dev_end.insert(0, "192.168.0.254")
        self.dev_end.pack(side="left", padx=(4, 8))
        self.btn_local = ttk.Button(bar, text="本机网段", command=self.fill_local_subnet)
        self.btn_local.pack(side="left")

        bar2 = ttk.Frame(tab, padding=(8, 2, 8, 2))
        bar2.grid(row=1, column=0, sticky="ew")
        self.btn_dev = ttk.Button(bar2, text="发现设备", command=self.start_device_scan)
        self.btn_dev.pack(side="left")
        self.btn_dev_export = ttk.Button(bar2, text="导出设备清单",
                                         command=self.export_devices, state="disabled")
        self.btn_dev_export.pack(side="left", padx=6)
        ttk.Label(bar2, text="（支持跨网段：填不同网段的起止 IP 即可）",
                  foreground="#777777").pack(side="left")
        self.lbl_dev = ttk.Label(bar2, text="共 0 台 / 视频设备 0 台", foreground="#333333")
        self.lbl_dev.pack(side="right")

        self.dev_bar = ttk.Progressbar(tab, mode="indeterminate")
        self.dev_bar.grid(row=2, column=0, sticky="ew", padx=8)

        cols = ("no", "ip", "dtype", "vendor", "model", "version", "serial",
                "mac", "status", "ports")
        heads = {"no": ("NO.", 45), "ip": ("IP地址", 110), "dtype": ("类型", 110),
                 "vendor": ("厂商", 90), "model": ("型号", 140),
                 "version": ("版本号", 115), "serial": ("序列号", 110),
                 "mac": ("MAC地址", 115), "status": ("状态", 65),
                 "ports": ("开放端口", 110)}
        wrap = ttk.Frame(tab)
        wrap.grid(row=3, column=0, sticky="nsew", padx=8, pady=8)
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        self._heads_dev = heads
        for c in cols:
            self.tree.column(c, width=heads[c][1], anchor="w", stretch=True)
        self._sortable_heading(self.tree, cols, heads, "dev")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.tree.tag_configure("cam", background="#E8F5E9")
        self.tree.tag_configure("other", background="#FFFFFF")
        self.tree.bind("<Double-1>", self.on_device_double_click)
        self.tree.bind("<Button-3>", self.on_device_right_click)

    # ==================== 海康 / 大华 独立页 ====================
    def _sort_tree(self, which, col):
        """点击表头排序：同列再点切换 升/降"""
        st = self._sort_state.setdefault(which, {"col": None, "desc": False})
        if st["col"] == col:
            st["desc"] = not st["desc"]        # 已在按该列排 → 反转
        else:
            st["col"], st["desc"] = col, False
        self._apply_sort(which)

    def _apply_sort(self, which):
        if which == "dev":
            recs, tree, heads = self.devices, self.tree, self._heads_dev
        elif which == "hik":
            recs, tree, heads = self.hik_records, self.hik_tree, self._heads_hik
        else:
            recs, tree, heads = self.dahua_records, self.dahua_tree, self._heads_dahua
        st = self._sort_state.setdefault(which, {"col": None, "desc": False})
        col, desc = st["col"], st["desc"]
        if col:
            try:
                recs.sort(key=lambda r: _col_sort_key(col, r), reverse=desc)
            except Exception:
                pass
        tree.delete(*tree.get_children())
        if which == "dev":
            self._refill_dev_tree()
        elif which == "hik":
            for i, r in enumerate(recs, 1):
                self._fill_hik_row(r, i)
        else:
            for i, r in enumerate(recs, 1):
                self._fill_dahua_row(r, i)
        for c, spec in heads.items():
            base = spec[0]
            if c == col:
                tree.heading(c, text=base + ("  ▼" if desc else "  ▲"))
            else:
                tree.heading(c, text=base)

    def _sortable_heading(self, tree, cols, heads, which):
        """给除 NO. 以外的列挂上点击排序"""
        for c in cols:
            if c == "no":
                tree.heading(c, text=heads[c][0])
            else:
                tree.heading(c, text=heads[c][0],
                             command=lambda c=c, w=which: self._sort_tree(w, c))

    def _make_tree(self, parent, cols, heads, row, which):
        wrap = ttk.Frame(parent)
        wrap.grid(row=row, column=0, sticky="nsew", padx=8, pady=8)
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)
        tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            tree.column(c, width=heads[c][1], anchor="w", stretch=True)
        if which == "hik":
            self._heads_hik = heads
        else:
            self._heads_dahua = heads
        self._sortable_heading(tree, cols, heads, which)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree.tag_configure("cam", background="#E8F5E9")
        tree.tag_configure("hist", background="#F7F7F7", foreground="#9AA0A6")
        tree.bind("<Double-1>", lambda e, t=tree: self._tree_long_ping(t))
        tree.bind("<Button-3>", lambda e, t=tree: self._tree_menu(e, t))
        return tree

    def _tree_long_ping(self, tree):
        sel = tree.selection()
        if not sel:
            return
        LongPingWindow(self.root, tree.item(sel[0], "values")[1])

    def _tree_menu(self, event, tree):
        row = tree.identify_row(event.y)
        if not row:
            return
        tree.selection_set(row)
        vals = tree.item(row, "values")
        ip = vals[1]
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=f"打开网页  http://{ip}",
                         command=lambda: self.open_web(ip, "http"))
        menu.add_command(label=f"打开网页  https://{ip}",
                         command=lambda: self.open_web(ip, "https"))
        menu.add_separator()
        menu.add_command(label="长Ping", command=lambda: LongPingWindow(self.root, ip))
        menu.add_command(label="复制IP", command=lambda: self.copy_text(ip))
        menu.add_command(label="复制本行信息",
                         command=lambda: self.copy_text(" | ".join(vals)))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _clear_tree(self, which):
        if which == "hik":
            self.hik_records.clear()
            tree, lbl = self.hik_tree, self.lbl_hik
        else:
            self.dahua_records.clear()
            tree, lbl = self.dahua_tree, self.lbl_dahua
        for item in tree.get_children():
            tree.delete(item)
        lbl.config(text="共 0 台")
        if which == "hik":
            self._hik_rows.clear()
        # 清空同时清掉历史缓存，避免下次启动又冒出来
        self._history[which] = []
        save_history(self._history)

    # ---------- 搜索历史（只用于补扫网段，启动不入表）----------
    def _save_hist(self):
        keys = ("ip", "mac", "model", "version", "serial")

        def merge(recs, old):
            """本次结果 + 缓存里本次没搜到的（保历史不丢）"""
            out = [{k: r.get(k) for k in keys} for r in recs]
            ips = {r.get("ip") for r in out}
            for o in old or []:
                if isinstance(o, dict) and o.get("ip") and o["ip"] not in ips:
                    out.append({k: o.get(k) for k in keys})
            return out

        self._history = {
            "hik": merge(self.hik_records, self._history.get("hik")),
            "dahua": merge(self.dahua_records, self._history.get("dahua")),
        }
        save_history(self._history)

    # ---------- 海康 SADP 页 ----------
    def _build_hik_tab(self):
        self.hik_records = []
        self.hik_running = False
        tab = self.tab_hik
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        bar = ttk.Frame(tab, padding=(8, 8, 8, 2))
        bar.grid(row=0, column=0, sticky="ew")
        self.btn_hik = ttk.Button(bar, text="搜索海康设备", command=self.start_hik_search)
        self.btn_hik.pack(side="left")
        self.btn_hik_stop = ttk.Button(bar, text="停止", state="disabled",
                                       command=self.stop_hik_search)
        self.btn_hik_stop.pack(side="left", padx=6)
        ttk.Button(bar, text="清空", command=lambda: self._clear_tree("hik")).pack(side="left")
        ttk.Button(bar, text="导出清单",
                   command=lambda: self.export_table("hik")).pack(side="left", padx=6)
        self.lbl_hik = ttk.Label(bar, text="共 0 台", foreground="#333333")
        self.lbl_hik.pack(side="right")

        self.hik_bar = ttk.Progressbar(tab, mode="indeterminate")
        self.hik_bar.grid(row=1, column=0, sticky="ew", padx=8)

        cols = ("no", "ip", "model", "serial", "version", "init", "http", "mac")
        heads = {"no": ("NO.", 45), "ip": ("IP地址", 115), "model": ("型号", 160),
                 "serial": ("序列号", 190), "version": ("版本号", 155),
                 "init": ("初始化状态", 95), "http": ("HTTP端口", 80),
                 "mac": ("MAC地址", 125)}
        self.hik_tree = self._make_tree(tab, cols, heads, 2, "hik")

    def _fill_hik_row(self, r, idx=None):
        self.hik_tree.insert("", "end", values=(
            idx or len(self.hik_records), r["ip"], r["model"], r["serial"],
            r["version"], r["init"], r["http"], r["mac"]),
            tags=("hist" if r.get("hist") else "cam",))

    def start_hik_search(self):
        if self.hik_running:
            return
        self.hik_running = True
        self.hik_stop_evt = threading.Event()
        self.btn_hik.config(state="disabled")
        self.btn_hik_stop.config(state="normal")
        self.hik_bar.start(12)
        # 点击搜索自动刷新
        self._refresh_tree("hik")
        self.nb.select(self.tab_hik)
        self.hik_ifaces = self.sel_ifaces()
        names = "、".join(self.iface_label(i) for i in
                          (self.hik_ifaces or [n["ip"] for n in self._nets]))
        self.status.config(text=f"正在发送 SADP 组播探测（网卡：{names}），"
                                f"没新设备后自动停止 ...")
        threading.Thread(target=self._hik_worker, daemon=True).start()

    def _hik_worker(self):
        """SADP 搜索：最少跑 MIN_RUN 秒，之后连续 IDLE_STOP 秒没有新设备就自动停。
        与大华页行为一致，不会一直转圈。"""
        seen = set()
        mac_table = {}
        MIN_RUN, IDLE_STOP, HARD_MAX = 12.0, 8.0, 60.0
        start = time.time()
        last_new = start
        try:
            while not self.hik_stop_evt.is_set():
                now = time.time()
                if now - start >= HARD_MAX:
                    break
                if now - start >= MIN_RUN and now - last_new >= IDLE_STOP:
                    break
                if not mac_table:
                    mac_table = read_arp()
                res = sadp_discover(2.5, ifaces=self.hik_ifaces)
                for ip, d in res.items():
                    if ip in seen:
                        continue
                    seen.add(ip)
                    last_new = time.time()
                    self.q.put(("hik_add", ip, d, mac_table.get(ip, "-")))
                time.sleep(0.3)
        finally:
            self.q.put(("hik_done", len(seen)))

    def stop_hik_search(self):
        if getattr(self, "hik_stop_evt", None):
            self.hik_stop_evt.set()
            self.btn_hik_stop.config(state="disabled")
            self.status.config(text="正在停止搜索 ...")

    # ---------- 大华页 ----------
    def _build_dahua_tab(self):
        self.dahua_records = []
        self.dahua_running = False
        self.dahua_targets = []
        self.dahua_ifaces = None
        self.dahua_unicast = False
        self.dahua_listen_sec = None   # None = 自适应：搜完自动停止
        tab = self.tab_dahua
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)
        _base = ".".join(get_local_ips()[0].split(".")[:3])

        r0 = ttk.Frame(tab, padding=(8, 8, 8, 2))
        r0.grid(row=0, column=0, sticky="ew")
        ttk.Label(r0, text="起始IP:").pack(side="left")
        self.dahua_start = ttk.Entry(r0, width=15, font=("Consolas", 10))
        self.dahua_start.insert(0, f"{_base}.1")
        self.dahua_start.pack(side="left", padx=(4, 8))
        ttk.Label(r0, text="结束IP:").pack(side="left")
        self.dahua_end = ttk.Entry(r0, width=15, font=("Consolas", 10))
        self.dahua_end.insert(0, f"{_base}.254")
        self.dahua_end.pack(side="left", padx=(4, 8))
        self.btn_dahua_scan = ttk.Button(r0, text="扫描该范围(37777)",
                                         command=self.dahua_quick_scan)
        self.btn_dahua_scan.pack(side="left")
        self.lbl_dahua = ttk.Label(r0, text="共 0 台", foreground="#333333")
        self.lbl_dahua.pack(side="right")

        r1 = ttk.Frame(tab, padding=(8, 2, 8, 2))
        r1.grid(row=1, column=0, sticky="ew")
        self.btn_dahua = ttk.Button(r1, text="搜索大华设备",
                                    command=self.start_dahua_listen)
        self.btn_dahua.pack(side="left")
        self.btn_dahua_stop = ttk.Button(r1, text="停止", state="disabled",
                                         command=self.stop_dahua_listen)
        self.btn_dahua_stop.pack(side="left", padx=6)
        ttk.Label(r1, text="指定IP:").pack(side="left", padx=(10, 2))
        self.dahua_ip = ttk.Entry(r1, width=18, font=("Consolas", 10))
        self.dahua_ip.pack(side="left")
        self.btn_dahua_uni = ttk.Button(r1, text="单播探测",
                                        command=self.dahua_unicast_probe)
        self.btn_dahua_uni.pack(side="left", padx=(4, 10))
        ttk.Button(r1, text="清空",
                   command=lambda: self._clear_tree("dahua")).pack(side="left")
        ttk.Button(r1, text="导出清单",
                   command=lambda: self.export_table("dahua")).pack(side="left", padx=6)

        self.dahua_bar = ttk.Progressbar(tab, mode="indeterminate")
        self.dahua_bar.grid(row=2, column=0, sticky="ew", padx=8)

        cols = ("no", "ip", "mac", "model", "version", "serial", "source")
        heads = {"no": ("NO.", 45), "ip": ("IP地址", 125), "mac": ("MAC地址", 135),
                 "model": ("型号", 165), "version": ("版本号", 145),
                 "serial": ("序列号", 170), "source": ("来源", 120)}
        self.dahua_tree = self._make_tree(tab, cols, heads, 3, "dahua")

    def _fill_dahua_row(self, r, idx=None):
        self.dahua_tree.insert("", "end", values=(
            idx or len(self.dahua_records), r["ip"], r.get("mac", "-"), r["model"],
            r["version"], r["serial"], r["source"]),
            tags=("hist" if r.get("hist") else "cam",))

    def start_dahua_listen(self, sec=None, targets=None, unicast=False):
        if self.dahua_running:
            return
        self.dahua_running = True
        self.dahua_stop = threading.Event()
        self.dahua_listen_sec = sec
        self.dahua_targets = list(targets or [])
        self.dahua_unicast = unicast   # True=只对 targets 单播，不发广播/组播
        # 完整搜索时，自动补扫历史记录里出现过的其它网段（跨网段只能靠单播）
        auto_ips = []
        if not sec and not self.dahua_targets:
            auto_ips = self._history_nets()
            if auto_ips:
                self.dahua_targets = auto_ips
        self.btn_dahua.config(state="disabled")
        self.btn_dahua_stop.config(state="normal")
        self.dahua_bar.start(12)
        # 点击搜索自动刷新：清掉在线行重新来，灰色"上次记录"保留
        self._refresh_tree("dahua")
        self.nb.select(self.tab_dahua)
        self.dahua_ifaces = self.sel_ifaces()
        ips = self.dahua_ifaces or [n["ip"] for n in self._nets]
        if auto_ips:
            pre = ", ".join(sorted({i.rsplit(".", 1)[0] for i in auto_ips}))
            extra = f"  自动补扫历史网段 {pre}.0/24"
        elif self.dahua_targets:
            extra = f"  单播目标 {len(self.dahua_targets)} 个"
        else:
            extra = ""
        mode = (f"{sec} 秒" if sec else
                "搜完自动停止（连续 8 秒无新设备即结束）")
        if unicast:
            self.status.config(
                text=f"正在单播探测 {len(self.dahua_targets)} 个指定 IP"
                     f"（只问它们，不发广播；{mode}）...")
        else:
            self.status.config(
                text=f"正在搜索大华设备（ConfigTool协议 v1/v2 组播+定向广播{extra}，"
                     f"{mode}）  网卡：{', '.join(ips)}")
        threading.Thread(target=self._dahua_worker, daemon=True).start()

    def _refresh_tree(self, which):
        """点击搜索时自动刷新：清空列表重新来"""
        recs = self.hik_records if which == "hik" else self.dahua_records
        recs.clear()
        if which == "hik":
            self._hik_rows.clear()   # 丢掉上一轮还没播完的行
        self._apply_sort(which)
        (self.lbl_hik if which == "hik" else self.lbl_dahua).config(
            text=f"共 {len(recs)} 台")

    @staticmethod
    def _parse_targets(raw):
        """解析目标：单个 IP / 多个(逗号) / 整段 192.168.1.1-254 / 192.168.1.0/24"""
        raw = (raw or "").replace("，", ",").replace("；", ",").replace(" ", ",")
        out = []
        for tok in re.split(r"[,;]+", raw):
            tok = tok.strip()
            if not tok:
                continue
            if "/" in tok:                       # 192.168.1.0/24
                base, _, bits = tok.partition("/")
                try:
                    socket.inet_aton(base)
                    n = int(bits)
                except (OSError, ValueError):
                    return [], f"网段写法不对：{tok}"
                if n != 24:
                    return [], "暂只支持 /24 网段，例如 192.168.1.0/24"
                pre = base.rsplit(".", 1)[0]
                out += [f"{pre}.{i}" for i in range(1, 255)]
                continue
            if "-" in tok:                       # 192.168.1.1-254
                a, _, b = tok.partition("-")
                a, b = a.strip(), b.strip()
                try:
                    socket.inet_aton(a)
                except OSError:
                    return [], f"起始 IP 不合法：{a}"
                pre = a.rsplit(".", 1)[0]
                try:
                    start = int(a.rsplit(".", 1)[1])
                except ValueError:
                    return [], f"起始 IP 不合法：{a}"
                if b.isdigit():
                    end = int(b)
                else:
                    try:
                        socket.inet_aton(b)
                    except OSError:
                        return [], f"结束 IP 不合法：{b}"
                    if b.rsplit(".", 1)[0] != pre:
                        return [], f"范围两端必须同一网段：{tok}"
                    end = int(b.rsplit(".", 1)[1])
                if end < start:
                    return [], f"范围写反了：{tok}"
                out += [f"{pre}.{i}" for i in range(start, end + 1)]
                continue
            try:
                socket.inet_aton(tok)
            except OSError:
                return [], f"不是合法 IP：{tok}"
            out.append(tok)
        seen, uniq = set(), []
        for ip in out:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)
        if len(uniq) > 254:
            return [], "一次最多 254 个目标，请缩小范围"
        return uniq, None

    def dahua_unicast_probe(self):
        """对指定 IP（或整段）做单播探测 —— 跨网段、广播到不了时用这个"""
        ips, err = self._parse_targets(self.dahua_ip.get())
        if err:
            messagebox.showerror("格式错误", err)
            return
        if not ips:
            messagebox.showinfo(
                "提示",
                "请先在“指定IP”里填目标，支持三种写法：\n"
                "  单个：192.168.1.108\n"
                "  多个：192.168.1.108, 192.168.1.64\n"
                "  整段：192.168.1.1-254  或  192.168.1.0/24")
            return
        self.start_dahua_listen(sec=15, targets=ips, unicast=True)

    def _dahua_worker(self):
        stats = {}

        def on_dev(ip, dev):
            self.q.put(("dahua_add", ip, dev))

        uni = getattr(self, "dahua_unicast", False)

        def search_thread():
            try:
                dahua_search(self.dahua_listen_sec, self.dahua_stop,
                             on_dev, stats, targets=self.dahua_targets,
                             ifaces=self.dahua_ifaces, unicast_only=uni)
            except Exception:
                pass
            finally:
                # 搜索结束（自适应/超时/手动）→ 心跳监听一起收工
                self.dahua_stop.set()

        t = threading.Thread(target=search_thread, daemon=True)
        t.start()
        if not uni:      # 单播探测不开心跳：心跳会把全网设备都带进来
            try:
                # 心跳监听跟搜索同生命周期；上限拉长，实际由 stop_event 控制
                dahua_heartbeat_listen(180.0, self.dahua_stop, on_dev, stats,
                                       ifaces=self.dahua_ifaces)
            except Exception:
                pass
        t.join(timeout=5)
        self.q.put(("dahua_done", len(self.dahua_records),
                    stats.get("packets", 0), stats.get("matched", 0),
                    stats.get("no5050", False)))

    def stop_dahua_listen(self):
        if getattr(self, "dahua_stop", None):
            self.dahua_stop.set()
        self.dahua_running = False
        self.btn_dahua.config(state="normal")
        self.btn_dahua_stop.config(state="disabled")
        self.dahua_bar.stop()
        self.status.config(text=f"已停止搜索 — 共收到 {len(self.dahua_records)} 台大华设备")

    def dahua_quick_scan(self):
        """扫描指定范围：先协议单播（拿型号/MAC/序列号），再端口探测兜底"""
        if self.dahua_running:
            return
        ips, err = build_ip_range(self.dahua_start.get(), self.dahua_end.get(),
                                  limit=2048)
        if err:
            messagebox.showerror("错误", err)
            return
        self.dahua_running = True
        self.dahua_stop = threading.Event()
        self.dahua_ifaces = self.sel_ifaces()
        self.dahua_scan_desc = f"{ips[0]} - {ips[-1]}"
        self.btn_dahua.config(state="disabled")
        self.btn_dahua_stop.config(state="normal")
        self.btn_dahua_scan.config(state="disabled")
        self.dahua_bar.start(12)
        # 点击扫描自动刷新：清掉在线行，保留灰色「上次记录」行
        self._refresh_tree("dahua")
        self.nb.select(self.tab_dahua)
        self.status.config(
            text=f"正在扫描 {ips[0]} - {ips[-1]}（共 {len(ips)} 个地址）："
                 f"协议单播 + 端口探测 ...")
        threading.Thread(target=self._dahua_scan_worker, args=(ips,),
                         daemon=True).start()

    def _dahua_scan_worker(self, ips):
        found = []
        try:
            # 第一步：ConfigTool 协议单播（跨网段可达，能拿到型号/MAC/序列号）
            try:
                dahua_search(timeout=min(20.0, 8.0 + len(ips) * 0.05),
                             stop_event=self.dahua_stop,
                             on_device=lambda ip, d: self.q.put(
                                 ("dahua_add", ip, dict(d))),
                             targets=ips[:254], ifaces=self.dahua_ifaces,
                             unicast_only=True)
            except Exception:
                pass
            if self.dahua_stop.is_set():
                return
            # 第二步：端口探测兜底（只判大华系，型号显示"-"）
            def chk(ip):
                if tcp_open(ip, 37777, 0.3) or \
                        (tcp_open(ip, 80, 0.3) and tcp_open(ip, 554, 0.3)):
                    found.append(ip)
                    self.q.put(("dahua_add", ip, {
                        "source": "端口扫描(37777)", "model": "-",
                        "version": "-", "serial": "-"}))
            with ThreadPoolExecutor(max_workers=128) as ex:
                list(ex.map(chk, ips))
        finally:
            self.dahua_stop.set()
            self.btn_dahua_stop.config(state="disabled")
            self.q.put(("dahua_scan_done", len(found)))

    # ---------- 独立清单导出 ----------
    def export_table(self, which):
        recs = self.hik_records if which == "hik" else self.dahua_records
        if not recs:
            messagebox.showinfo("提示", "列表为空，请先执行搜索/监听")
            return
        if which == "hik":
            fields = [("ip", "IP地址"), ("model", "型号"), ("serial", "序列号"),
                      ("version", "版本号"), ("init", "初始化状态"),
                      ("http", "HTTP端口"), ("mac", "MAC地址")]
            default = f"海康设备清单_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        else:
            fields = [("ip", "IP地址"), ("model", "型号"), ("version", "版本号"),
                      ("serial", "序列号"), ("source", "来源")]
            default = f"大华设备清单_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        path = filedialog.asksaveasfilename(
            title="导出清单", defaultextension=".csv", initialfile=default,
            filetypes=[("CSV 文件", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["序号"] + [n for _, n in fields])
                for i, r in enumerate(recs, 1):
                    w.writerow([i] + [r.get(k, "") for k, _ in fields])
                w.writerow([])
                w.writerow(["合计", f"{len(recs)} 台",
                            f"导出时间 {time.strftime('%Y-%m-%d %H:%M:%S')}"])
            messagebox.showinfo("提示", f"已导出:\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败：{e}")

    def fill_local_subnet(self):
        ip = get_local_ip()
        base = ".".join(ip.split(".")[:3])
        for entry, tail in ((self.dev_start, "1"), (self.dev_end, "254")):
            entry.delete(0, "end")
            entry.insert(0, f"{base}.{tail}")
        self.status.config(text=f"本机 IP: {ip}（已填入本机网段）")

    def start_device_scan(self):
        ips, err = build_ip_range(self.dev_start.get(), self.dev_end.get())
        if err:
            messagebox.showerror("错误", err)
            return
        if self.dev_scanning:
            return
        self.dev_scanning = True
        self.dev_gen += 1
        gen = self.dev_gen
        self.dev_range_desc = f"{ips[0]}-{ips[-1]}"
        self.devices.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.btn_dev.config(state="disabled")
        self.btn_dev_export.config(state="disabled")
        self.lbl_dev.config(text="共 0 台 / 视频设备 0 台")
        self.dev_bar.start(12)
        self.status.config(
            text=f"正在发现 {ips[0]} - {ips[-1]} 的设备（共 {len(ips)} 个地址）...")
        ifaces = self.sel_ifaces()      # 主线程取，子线程不碰 Tk
        threading.Thread(target=self._device_scan_worker, args=(ips, gen, ifaces),
                         daemon=True).start()

    def _device_scan_worker(self, ips, gen, ifaces=None):
        try:
            ipset = set(ips)
            total = len(ips)
            alive = {}

            def do_ping(ip):
                ok, lat = ping_once(ip, 700)
                if ok:
                    alive[ip] = lat

            self.q.put(("dev_progress", gen,
                        f"第 1 步：正在 Ping 扫描 {total} 个地址 ..."))
            with ThreadPoolExecutor(max_workers=128) as ex:
                list(ex.map(do_ping, ips))

            self.q.put(("dev_progress", gen, "第 2 步：TCP 端口预扫描（发现禁 Ping 的设备）..."))
            pre_ports = (80, 443, 554, 8000, 37777)
            tcp_open_ips = {}

            def pre(ip):
                found = [p for p in pre_ports if tcp_open(ip, p, 0.25)]
                if found:
                    tcp_open_ips[ip] = found

            with ThreadPoolExecutor(max_workers=128) as ex:
                list(ex.map(pre, ips))

            self.q.put(("dev_progress", gen, "第 3 步：读取 ARP 表获取 MAC ..."))
            arp = read_arp()

            self.q.put(("dev_progress", gen,
                        "第 4 步：组播发现（海康SADP / ONVIF / 大华心跳）..."))
            discovered = broadcast_discover(6.0, ifaces=ifaces)

            # 范围内候选 + 组播发现的跨网段设备（对标 ConfigTool）
            cand_set = {ip for ip in list(alive) + list(arp) + list(tcp_open_ips)
                        if ip in ipset}
            cand_set |= set(discovered)
            candidates = sorted(cand_set, key=ip_to_int)

            self_ip = get_local_ip()

            def probe(ip):
                mac = arp.get(ip, "")
                ports = scan_ports(ip)
                banners = {}
                if 80 in ports:
                    banners["http"] = http_probe(ip, 80)
                    # 海康 ISAPI / 大华 RPC2 认证挑战，用于厂商指纹
                    banners["isapi"] = http_probe(ip, 80, path="/ISAPI/System/deviceInfo")
                    banners["rpc2"] = http_probe(ip, 80, path="/RPC2_Login")
                if 443 in ports:
                    banners["https"] = https_probe(ip, 443)
                if 554 in ports:
                    banners["rtsp"] = rtsp_probe(ip, 554)
                vendor, dtype = classify(ip, mac, ports, banners)
                banner = short_banner(banners)

                disc = discovered.get(ip)
                model = version = serial = init = ""
                if disc:
                    hint = disc.get("dtype") or disc.get("kind")
                    if hint == "nvr":
                        dtype = "录像机(NVR/DVR)"
                    elif hint == "camera":
                        dtype = "摄像机(IPC)"
                    if disc.get("vendor"):
                        vendor = disc["vendor"]
                    elif not vendor or vendor == "未识别":
                        vendor = f'{disc.get("source", "组播")}设备'
                    model = disc.get("model", "")
                    version = disc.get("version", "")
                    serial = disc.get("serial", "")
                    init = disc.get("init", "")
                    if model:
                        banner = f"型号 {model}" + (f" | {banner}" if banner else "")
                else:
                    # 从网页指纹中提取型号
                    m = re.search(r"\b((?:DS|DH|IPC)-[A-Z0-9\-]{4,})\b", banner, re.I)
                    if m:
                        model = m.group(1).upper()

                is_self = ip == self_ip
                if is_self:
                    mac = mac or "(本机)"
                    vendor = "本机"
                return {
                    "ip": ip, "mac": mac or "-",
                    "vendor": vendor or "未识别",
                    "dtype": dtype,
                    "model": model or "-",
                    "version": version or "-",
                    "serial": serial or "-",
                    "init": init or "-",
                    "status": "本机" if is_self else ("在线" if ip in alive else "未响应ICMP"),
                    "ports": ", ".join(
                        f"{p}({PROBE_PORTS.get(p, '')})" for p in ports) or "-",
                    "banner": banner or "-",
                    "alive": ip in alive or bool(disc),
                }

            self.q.put(("dev_progress", gen,
                        f"第 5 步：正在识别 {len(candidates)} 台设备的类型 ..."))
            count = 0
            with ThreadPoolExecutor(max_workers=32) as ex:
                for dev in ex.map(probe, candidates):
                    # 过滤 ARP 残留：既 ping 不通、又没有开放端口的条目不是有效设备
                    if not dev["alive"] and dev["ports"] == "-":
                        continue
                    count += 1
                    self.q.put(("dev_progress", gen,
                                f"正在识别设备：{dev['ip']}  已确认 {count} 台"))
                    # 边识别边出结果（表格按当前排序规则保持有序）
                    self.q.put(("dev_add", gen, dev))
            self.q.put(("dev_done", gen, count))
        except Exception as e:
            self.q.put(("dev_progress", gen, f"设备发现出错：{e}"))
            self.q.put(("dev_done", gen, len(self.devices)))

    def _refill_dev_tree(self):
        tree = self.tree
        tree.delete(*tree.get_children())
        for i, dev in enumerate(self.devices, 1):
            tag = ("cam" if dev["dtype"].startswith(("视频", "摄像机", "录像机"))
                   else "other")
            tree.insert("", "end", values=(
                i, dev["ip"], dev["dtype"], dev["vendor"], dev["model"],
                dev["version"], dev["serial"], dev["mac"],
                dev["status"], dev["ports"]), tags=(tag,))

    def _add_device_row(self, dev):
        self.devices.append(dev)
        if self._can_append_tail("dev", dev):
            tag = ("cam" if dev["dtype"].startswith(("视频", "摄像机", "录像机"))
                   else "other")
            self.tree.insert("", "end", values=(
                len(self.devices), dev["ip"], dev["dtype"], dev["vendor"],
                dev["model"], dev["version"], dev["serial"], dev["mac"],
                dev["status"], dev["ports"]), tags=(tag,))
        elif self._sort_state.get("dev", {}).get("col"):
            self._apply_sort("dev")       # 已排序状态下随时保持有序
        else:
            tag = ("cam" if dev["dtype"].startswith(("视频", "摄像机", "录像机"))
                   else "other")
            self.tree.insert("", "end", values=(
                len(self.devices), dev["ip"], dev["dtype"], dev["vendor"],
                dev["model"], dev["version"], dev["serial"], dev["mac"],
                dev["status"], dev["ports"]), tags=(tag,))
        cam = sum(1 for d in self.devices
                  if d["dtype"].startswith(("视频", "摄像机", "录像机")))
        self.lbl_dev.config(text=f"共 {len(self.devices)} 台 / 视频设备 {cam} 台")
        # 同步到海康/大华独立页（按 IP 去重）
        vendor = dev.get("vendor") or ""
        if "大华" in vendor:
            if not any(r["ip"] == dev["ip"] for r in self.dahua_records):
                self.q.put(("dahua_add", dev["ip"], {
                    "source": "设备发现", "mac": dev.get("mac") or "-",
                    "model": dev.get("model") or "-",
                    "version": dev.get("version") or "-",
                    "serial": dev.get("serial") or "-"}))
        elif "海康" in vendor:
            if not any(r["ip"] == dev["ip"] for r in self.hik_records):
                rec = {"ip": dev["ip"], "model": dev.get("model") or "-",
                       "serial": dev.get("serial") or "-",
                       "version": dev.get("version") or "-",
                       "init": dev.get("init") or "-",
                       "http": "-", "mac": dev.get("mac") or "-"}
                self.hik_records.append(rec)
                if self._sort_state.get("hik", {}).get("col"):
                    self._apply_sort("hik")
                else:
                    self._fill_hik_row(rec)
                self.lbl_hik.config(text=f"共 {len(self.hik_records)} 台")

    def _selected_ip(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.item(sel[0], "values")[1]

    def on_device_double_click(self, event):
        ip = self._selected_ip()
        if ip:
            LongPingWindow(self.root, ip)

    def on_device_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        vals = self.tree.item(row, "values")
        ip = vals[1]
        dev = self._dev_record(ip)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=f"打开网页  http://{ip}",
                         command=lambda: self.open_web(ip, "http"))
        menu.add_command(label=f"打开网页  https://{ip}",
                         command=lambda: self.open_web(ip, "https"))
        if dev and "8080" in dev["ports"]:
            menu.add_command(label="打开网页  http://%s:8080" % ip,
                             command=lambda: self.open_web(ip, "http", 8080))
        menu.add_separator()
        menu.add_command(label="长Ping", command=lambda: LongPingWindow(self.root, ip))
        menu.add_command(label="复制IP", command=lambda: self.copy_text(ip))
        menu.add_command(label="复制本行信息",
                         command=lambda: self.copy_text(" | ".join(vals)))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def export_devices(self):
        if not self.devices:
            messagebox.showinfo("提示", "请先执行“发现设备”")
            return
        path = filedialog.asksaveasfilename(
            title="导出设备清单", defaultextension=".csv",
            initialfile=f"设备清单_{self.dev_range_desc.replace('.', '_').replace('-', '_')}"
                        f"_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            filetypes=[("CSV 文件", "*.csv")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["序号", "IP地址", "类型", "厂商", "型号", "版本号",
                            "序列号", "初始化状态", "MAC地址", "状态", "开放端口",
                            "标识信息"])
                for i, d in enumerate(self.devices, 1):
                    w.writerow([i, d["ip"], d["dtype"], d["vendor"], d["model"],
                                d["version"], d["serial"], d["init"], d["mac"],
                                d["status"], d["ports"], d["banner"]])
                cam = sum(1 for d in self.devices
                          if d["dtype"].startswith(("视频", "摄像机", "录像机")))
                w.writerow([])
                w.writerow(["汇总", f"扫描范围 {self.dev_range_desc}",
                            f"设备总数 {len(self.devices)} 台",
                            f"其中视频监控设备 {cam} 台",
                            f"导出时间 {time.strftime('%Y-%m-%d %H:%M:%S')}"])
            messagebox.showinfo("提示", f"设备清单已导出:\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败：{e}")


def main():
    # 高分屏清晰化：不声明 DPI 感知会被系统拉伸导致字体发虚
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", root.winfo_fpixels("1i") / 72.0)
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
