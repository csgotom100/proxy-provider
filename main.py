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
        name = urllib.parse.quote(p['name'])
        if p['type'] == 'hysteria2':
            return f"hy2://{p['password']}@{p['server']}:{p['port']}?insecure=1&sni={p.get('sni','')}#{name}"
        elif p['type'] == 'ss':
            auth = base64.b64encode(f"{p['cipher']}:{p['password']}".encode()).decode()
            return f"ss://{auth}@{p['server']}:{p['port']}#{name}"
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
                            nodes.append({"name": out.get("type").upper(), "type": out['type'].replace("shadowsocks","ss"), "server": out['server'], "port": out['server_port'], "uuid": out.get("uuid"), "password": out.get("password"), "cipher": out.get("method"), "sni": out.get("tls", {}).get("server_name")})
    except: pass
    return nodes

def process_node(proxy):
    server = proxy.get('server')
    port = proxy.get('port')
    if not server or not port: return None
    
    delay, ip = get_tcp_delay(server, port)
    if delay is not None:
        location = get_location(ip)
        # 核心：使用北京时间
        now_beijing = datetime.now(BEIJING_TZ).strftime("%H:%M")
        
        # 注入 TLS 分片与 Meta 参数
        if proxy.get('type') in ['vless', 'trojan', 'vmess', 'hysteria2', 'juicity']:
            proxy['client-fingerprint'] = 'chrome'
            proxy['tls-fragment'] = "10-30,5-10"
            proxy['tfo'] = True
            
        p_type = proxy.get('type', 'proxy').upper()
        proxy['_geo'] = location
        proxy['name'] = f"[{location}] {p_type}_{server} [{delay}ms] ({now_beijing})"
        return proxy
    return None

if __name__ == "__main__":
    start_time = time.time()
    urls = []
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
            urls = re.findall(r'https?://[^\s",\]]+', f.read())
    
    unique_proxies = {}
    for url in urls:
        for node in parse_remote(url):
            key = (str(node.get('server')).lower(), int(node.get('port')), str(node.get('type')).lower())
            if key not in unique_proxies: unique_proxies[key] = node

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        final_nodes = [r for r in executor.map(process_node, list(unique_proxies.values())) if r]

    if final_nodes:
        with open(TEMPLATE_FILE, 'r', encoding='utf-8') as f:
            tpl = yaml.safe_load(f)
        
        tpl['proxies'] = final_nodes
        shards = {"香港": "🇭🇰 香港节点", "美国": "🇺🇸 美国节点", "日本": "🇯🇵 日本节点", "新加坡": "🇸🇬 新加坡节点"}
        all_names = [n['name'] for n in final_nodes]
        
        for g in tpl.get('proxy-groups', []):
            if g['name'] in ['🚀 节点选择', '⚡ 自动选择']:
                g['proxies'] = all_names if g['name'] == '⚡ 自动选择' else g['proxies'] + all_names
            for reg, group_target in shards.items():
                if g['name'] == group_target:
                    g['proxies'] = [n['name'] for n in final_nodes if reg in n['_geo']]
            if g['name'] == '🌍 剩余地区':
                g['proxies'] = [n['name'] for n in final_nodes if not any(r in n['_geo'] for r in shards.keys())]

        with open(f"{OUTPUT_DIR}/clash_config.yaml", 'w', encoding='utf-8') as f:
            yaml.dump(tpl, f, sort_keys=False, allow_unicode=True)

        links = [to_link(n) for n in final_nodes if to_link(n)]
        with open(f"{OUTPUT_DIR}/node_links.txt", 'w', encoding='utf-8') as f:
            f.write("\n".join(links))

        with open(f"{OUTPUT_DIR}/subscribe_base64.txt", 'w', encoding='utf-8') as f:
            f.write(base64.b64encode("\n".join(links).encode()).decode())

    print(f"🎉 完成! 有效节点: {len(final_nodes)} 北京时间: {datetime.now(BEIJING_TZ).strftime('%Y-%m-%d %H:%M:%S')}")
