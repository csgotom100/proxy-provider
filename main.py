import yaml
import json
import urllib.request
import codecs
import socket
import time
import re
import base64
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- 基础配置 ---
TIMEOUT = 2.5            # 测速超时
MAX_THREADS = 50         # 并行线程数
SOURCE_FILE = './urls/manual_json.txt'
TEMPLATE_FILE = './templates/clash_template.yaml'
OUTPUT_DIR = './sub'
GEO_CACHE = {}

# 确保输出目录存在
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- 工具函数 ---
def get_location(ip):
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode('utf-8'))
            if data.get('status') == 'success':
                loc = data.get('country', '未知')
                GEO_CACHE[ip] = loc
                return loc
    except: pass
    return "未知"

def get_tcp_delay(server, port):
    start_time = time.time()
    try:
        ip = socket.gethostbyname(server)
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
        sock.close()
        return int((time.time() - start_time) * 1000), ip
    except: return None, None

def to_link(p):
    """简单转换为通用链接用于生成 txt 订阅"""
    try:
        name = urllib.parse.quote(p['name'])
        if p['type'] == 'hysteria2':
            return f"hy2://{p['password']}@{p['server']}:{p['port']}?insecure=1&sni={p.get('sni','')}#{name}"
        elif p['type'] == 'ss':
            auth = base64.b64encode(f"{p['cipher']}:{p['password']}".encode()).decode()
            return f"ss://{auth}@{p['server']}:{p['port']}#{name}"
    except: return None

# --- 核心处理逻辑 ---
def parse_remote(url):
    nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as res:
            raw = res.read().decode('utf-8')
            
            # 1. YAML 格式 (Clash / ShadowQUIC)
            if "clash" in url or "shadowquic" in url or url.endswith(".yaml"):
                data = yaml.safe_load(raw)
                nodes = data.get('proxies', [])
            
            # 2. JSON 格式 (Hysteria2 / Sing-box / Juicity 等)
            else:
                jd = json.loads(raw)
                if "juicity" in url:
                    s, p = jd["server"].split(":")
                    nodes = [{"name":"Juicity","type":"juicity","server":s,"port":int(p),"uuid":jd.get("uuid"),"sni":jd.get("sni"),"pinned-certchain-sha256":jd.get("pinned_certchain_sha256")}]
                elif "mieru" in url:
                    profile = jd.get("profiles", [{}])[0]
                    nodes = [{"name":"Mieru","type":"mieru","server":jd.get("server"),"port":jd.get("port"),"username":profile.get("username"),"password":profile.get("password"),"transport":profile.get("transport","tcp")}]
                elif "naiveproxy" in url:
                    match = re.search(r'https://(.*):(.*)@(.*)', jd.get("proxy", ""))
                    if match:
                        nodes = [{"name":"Naive","type":"socks5","server":match.group(3),"port":443,"username":match.group(1),"password":match.group(2),"tls":True}]
                elif "hysteria2" in url:
                    s, p =
