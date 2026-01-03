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

# --- 配置 ---
TIMEOUT = 10.0           
MAX_THREADS = 50
FILTER_DEAD_NODES = False 
SOURCE_FILE = './urls/manual_json.txt'
TEMPLATE_FILE = './templates/clash_template.yaml'
OUTPUT_DIR = './sub'
BEIJING_TZ = timezone(timedelta(hours=8))

os.makedirs(OUTPUT_DIR, exist_ok=True)
GEO_CACHE = {}

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
    """生成通用订阅链接"""
    try:
        name = urllib.parse.quote(p.get('name', 'Proxy'))
        srv, prt = p.get('server'), p.get('port')
        if not srv or not prt: return None
        ptype = p.get('type', '').lower()
        
        if ptype == 'vless':
            uuid = p.get('uuid')
            # 基础参数
            link = f"vless://{uuid}@{srv}:{prt}?encryption=none"
            # TLS/REALITY 参数
            security = p.get('security', 'none')
            link += f"&security={security}"
            if p.get('sni'): link += f"&sni={p.get('sni')}"
            
            if p.get('reality'):
                r = p['reality']
                link += f"&fp={r.get('fp','chrome')}&pbk={r.get('pbk')}&sid={r.get('sid')}"
            
            # 传输层
            if p.get('network') == 'xhttp':
                link += f"&type=xhttp&path={urllib.parse.quote(p.get('path','/'))}"
            
            return f"{link}#{name}"
            
        elif ptype == 'hysteria2':
            return f"hy2://{p.get('password','')}@{srv}:{prt}?insecure=1&sni={p.get('sni','')}#{name}"
        elif ptype == 'juicity':
            return f"juicity://{p.get('uuid')}@{srv}:{prt}?sni={p.get('sni')}#{name}"
        elif ptype == 'socks5':
            return f"socks5://{p.get('username')}:{p.get('password')}@{srv}:{prt}#{name}"
    except: return None
    return None

def parse_remote(url):
    nodes = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as res:
            raw = res.read().decode('utf-8')
            data = yaml.safe_load(raw)
            if not isinstance(data, dict): return []

            # --- 识别 Sing-box 格式 (outbounds 包含 type) ---
            if "outbounds" in data:
                for out in data["outbounds"]:
                    # 仅抓取代理类协议
                    if out.get("type") in ["vless", "shadowsocks", "trojan", "hysteria2", "tuic"]:
                        # 兼容 Sing-box 字段名 (server_port) 与 Xray 字段名 (port)
                        port = out.get("server_port") or out.get("port")
                        server = out.get("server")
                        if not server or not port: continue
                        
                        node = {
                            "name": "SB_" + out.get("type").upper(),
                            "type": out.get("type"),
                            "server": server,
                            "port": int(port),
                            "uuid": out.get("uuid"),
                            "password": out.get("password")
                        }
                        
                        # 处理 Sing-box 嵌套的 TLS/REALITY
                        tls_conf = out.get("tls", {})
                        if tls_conf.get("enabled"):
                            node["security"] = "reality" if tls_conf.get("reality", {}).get("enabled") else "tls"
                            node["sni"] = tls_conf.get("server_name")
                            if node["security"] == "reality":
                                ry = tls_conf.get("reality", {})
                                node["reality"] = {
                                    "pbk": ry.get("public_key"),
                                    "sid": ry.get("short_id"),
                                    "fp": tls_conf.get("utls", {}).get("fingerprint", "chrome")
                                }
                        
                        # 处理 Xray 标准 outbounds 格式 (settings 嵌套)
                        if out.get("settings") and "vnext" in out["settings"]:
                            vnext = out["settings"]["vnext"][0]
                            node["server"] = vnext["address"]
                            node["port"] = vnext["port"]
                            node["uuid"] = vnext["users"][0]["id"]
                            
                        nodes.append(node)

            # --- 识别单节点 JSON 格式 ---
            elif data.get("proxy") and "https://" in data.get("proxy"):
                m = re.search(r'https://(.*):(.*)@(.*):(\d+)', data.get("proxy"))
                if m: nodes.append({"name":"Naive","type":"socks5","server":m.group(3),"port":int(m.group(4)),"username":m.group(1),"password":m.group(2),"tls":True})
            elif data.get("auth") or data.get("congestion_control"):
                m = re.search(r'([\d\.]+):(\d+)', data.get("server", ""))
                if m:
                    t = "hysteria2" if data.get("auth") else "juicity"
                    nodes.append({"name":t.capitalize(),"type":t,"server":m.group(1),"port":int(m.group(2)),"password":data.get("auth"),"uuid":data.get("uuid"),"sni":data.get("sni")})
            elif 'proxies' in data:
                nodes = data.get('proxies', [])

    except Exception as e: print(f"ERROR: {url} 失败: {e}")
    return nodes

def process_node(proxy):
    srv, prt = proxy.get('server'), proxy.get('port')
    if not srv or not prt: return None
    delay, ip = get_tcp_delay(srv, prt)
    if delay is None:
        if FILTER_DEAD_NODES: return None
        delay, ip = 0, srv 
    loc = get_location(ip) if delay > 0 else "未知"
    now = datetime.now(BEIJING_TZ).strftime("%H:%M")
    proxy['client-fingerprint'] = 'chrome'
    proxy['tfo'] = True
    p_t = proxy.get('type', 'proxy').upper()
    proxy['_geo'] = loc
    proxy['name'] = f"[{loc}] {p_t}_{srv} [{delay}ms] ({now})"
    return proxy

if __name__ == "__main__":
    urls = []
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
            urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    unique_proxies = {}
    for url in urls:
        for node in parse_remote(url.strip()):
            s, p, t = node.get('server'), node.get('port'), node.get('type')
            if s and p and t:
                key = (str(s).lower(), int(p), str(t).lower())
                if key not in unique_proxies: unique_proxies[key] = node
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        final_nodes = [r for r in executor.map(process_node, list(unique_proxies.values())) if r]
    if os.path.exists(TEMPLATE_FILE):
        with open(TEMPLATE_FILE, 'r', encoding='utf-8') as f:
            tpl = yaml.safe_load(f)
        tpl['proxies'] = final_nodes
        all_n = [n['name'] for n in final_nodes]
        for g in tpl.get('proxy-groups', []):
            if g['name'] in ['🚀 节点选择', '⚡ 自动选择']:
                g['proxies'] = all_n if g['name'] == '⚡ 自动选择' else g['proxies'] + all_n
        with open(f"{OUTPUT_DIR}/clash_config.yaml", 'w', encoding='utf-8') as f:
            yaml.dump(tpl, f, sort_keys=False, allow_unicode=True)
    links = [to_link(n) for n in final_nodes if to_link(n)]
    with open(f"{OUTPUT_DIR}/node_links.txt", 'w', encoding='utf-8') as f:
        f.write("\n".join(links))
    print(f"🎉 任务结束! 共解析: {len(final_nodes)} 个节点")
