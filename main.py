import yaml
import json
import urllib.request
import codecs
import socket
import time
import re
import base64
import os
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# --- 基础配置 ---
TIMEOUT = 2.5
MAX_THREADS = 50
SOURCE_FILE = './urls/manual_json.txt'
TEMPLATE_FILE = './templates/clash_template.yaml'
OUTPUT_DIR = './sub'
# 定义北京时区 (UTC+8)
BEIJING_TZ = timezone(timedelta(hours=8))

os.makedirs(OUTPUT_DIR, exist_ok=True)
GEO_CACHE = {}

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
    try:
        name = urllib.parse.quote(p.get('name', 'Proxy'))
        srv = p.get('server')
        prt = p.get('port')
        if not srv or not prt: return None
        
        if p['type'] == 'hysteria2':
            return f"hy2://{p.get('password','')}@{srv}:{prt}?insecure=1&sni={p.get('sni','')}#{name}"
        elif p['type'] == 'ss':
            method = p.get('cipher')
            passwd = p.get('password')
            if not method or not passwd: return None
            auth = base64.b64encode(f"{method}:{passwd}".encode()).decode()
            return f"ss://{auth}@{srv}:{prt}#{name}"
    except: return None

# --- 解析与处理 ---
def parse_remote(url):
    nodes = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as res:
            raw = res.read().decode('utf-8')
            if "clash" in url or "shadowquic" in url or url.endswith(".yaml"):
                data = yaml.safe_load(raw)
                if data and 'proxies' in data:
                    nodes = data.get('proxies', [])
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
                    s, p = jd["server"].split(":")
                    nodes = [{"name":"Hys2","type":"hysteria2","server":s,"port":int(p),"password":jd.get("auth"),"sni":jd.get("server_name"),"skip-cert-verify":True}]
                else:
                    outbounds = jd.get("outbounds", [])
                    for out in outbounds:
                        if out.get("server") and out.get("type") not in ["direct", "block", "dns"]:
                            nodes.append({
                                "name": out.get("type").upper(), 
                                "type": out['type'].replace("shadowsocks","ss"), 
                                "server": out['server'], 
                                "port": out['server_port'], 
                                "uuid": out.get("uuid"), 
                                "password": out.get("password"), 
                                "cipher": out.get("method"), 
                                "sni": out.get("tls", {}).get("server_name")
                            })
    except: pass
    return nodes

def process_node(proxy):
    server = proxy.get('server')
    port = proxy.get('port')
    if not server or not port: return None
    
    delay, ip = get_tcp_delay(server, port)
    if delay is not None:
        location = get_location(ip)
        now_beijing = datetime.now(BEIJING_TZ).strftime("%H:%M")
        
        if proxy.get('type') in ['vless', 'trojan', 'vmess', 'hysteria2', '
