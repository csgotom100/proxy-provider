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

# --- 核心策略配置 ---
TIMEOUT = 10.0           # 测速超时延长到 10 秒
MAX_THREADS = 50
FILTER_DEAD_NODES = False # 【重要修改】设为 False，则即便测速不通也保留节点（仅标记延迟为 0）
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
    try:
        name = urllib.parse.quote(p.get('name', 'Proxy'))
        srv, prt = p.get('server'), p.get('port')
        if not srv or not prt: return None
        ptype = p.get('type', '').lower()
        if ptype == 'hysteria2':
            pw, sn = p.get('password',''), p.get('sni','')
            return f"hy2://{pw}@{srv}:{prt}?insecure=1&sni={sn}#{name}"
        elif ptype == 'ss':
            m, pw = p.get('cipher'), p.get('password')
            if not m or not pw: return None
            auth = base64.b64encode(f"{m}:{pw}".encode()).decode()
            return f"ss://{auth}@{srv}:{prt}#{name}"
        elif ptype == 'vless':
            uuid = p.get('uuid')
            sni = p.get('sni', '')
            return f"vless://{uuid}@{srv}:{prt}?encryption=none&security=tls&sni={sni}#{name}"
        elif ptype == 'trojan':
            pw, sni = p.get('password'), p.get('sni', '')
            return f"trojan://{pw}@{srv}:{prt}?security=tls&sni={sni}#{name}"
        elif ptype == 'vmess':
            v_conf = {"v":"2","ps":p.get('name'),"add":srv,"port":prt,"id":p.get('uuid'),"aid":"0","net":"tcp","type":"none","tls":"tls"}
            v_b64 = base64.b64encode(json.dumps(v_conf).encode()).decode()
            return f"vmess://{v_b64}"
    except: return None
    return None

def parse_remote(url):
    nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        print(f"DEBUG: 正在尝试抓取源: {url}")
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as res:
            raw = res.read().decode('utf-8')
            if "clash" in url or "shadowquic" in url or url.endswith((".yaml", ".yml")):
                data = yaml.safe_load(raw)
                if data and 'proxies' in data: nodes = data.get('proxies', [])
            else:
                jd = json.loads(raw)
                if "juicity" in url:
                    s, p = jd["server"].split(":")
                    nodes = [{"name":"Juicity","type":"juicity","server":s,"port":int(p),"uuid":jd.get("uuid"),"sni":jd.get("sni")}]
                elif "hysteria2" in url:
                    s, p = jd["server"].split(":")
                    nodes = [{"name":"Hys2","type":"hysteria2","server":s,"port":int(p),"password":jd.get("auth"),"sni":jd.get("server_name")}]
                else:
                    for out in jd.get("outbounds", []):
                        if out.get("server") and out.get("type") not in ["direct", "block", "dns"]:
                            nodes.append({"name":out.get("type").upper(),"type":out['type'].replace("shadowsocks","ss"),"server":out['server'],"port":out['server_port'],"uuid":out.get("uuid"),"password":out.get("password"),"cipher":out.get("method"),"sni":out.get("tls",{}).get("server_name")})
        print(f"INFO: 源 {url} 返回了 {len(nodes)} 个原始节点")
    except Exception as e: print(f"ERROR: 抓取 {url} 失败: {e}")
    return nodes

def process_node(proxy):
    srv, prt = proxy.get('server'), proxy.get('port')
    if not srv or not prt: return None
    delay, ip = get_tcp_delay(srv, prt)
    
    # 如果测速失败但设置了不带过滤，则给个 0ms 延迟并继续
    if delay is None:
        if FILTER_DEAD_NODES: return None
        delay = 0
        ip = srv # 测速失败无法获取真实IP，使用域名代替

    loc = get_location(ip) if delay > 0 else "未知"
    now = datetime.now(BEIJING_TZ).strftime("%H:%M")
    
    tls_types = ['vless', 'trojan', 'vmess', 'hysteria2', 'juicity']
    if proxy.get('type') in tls_types:
        proxy['client-fingerprint'] = 'chrome'
        proxy['tls-fragment'] = "10-30,5-10"
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
                try:
                    key = (str(s).lower(), int(p), str(t).lower())
                    if key not in unique_proxies: unique_proxies[key] = node
                except: continue

    print(f"INFO: 去重后总计 {len(unique_proxies)} 个节点，开始并发处理...")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        final_nodes = [r for r in executor.map(process_node, list(unique_proxies.values())) if r]

    if os.path.exists(TEMPLATE_FILE):
        with open(TEMPLATE_FILE, 'r', encoding='utf-8') as f:
            tpl = yaml.safe_load(f)
        tpl['proxies'] = final_nodes
        shards = {"香港":"🇭🇰 香港节点","美国":"🇺🇸 美国节点","日本":"🇯🇵 日本节点","新加坡":"🇸🇬 新加坡节点"}
        all_n = [n['name'] for n in final_nodes]
        for g in tpl.get('proxy-groups', []):
            if g['name'] in ['🚀 节点选择', '⚡ 自动选择']:
                g['proxies'] = all_n if g['name'] == '⚡ 自动选择' else g['proxies'] + all_n
            for reg, target in shards.items():
                if g['name'] == target:
                    g['proxies'] = [n['name'] for n in final_nodes if reg in n['_geo']]
            if g['name'] == '🌍 剩余地区':
                g['proxies'] = [n['name'] for n in final_nodes if not any(r in n['_geo'] for r in shards.keys())]
        with open(f"{OUTPUT_DIR}/clash_config.yaml", 'w', encoding='utf-8') as f:
            yaml.dump(tpl, f, sort_keys=False, allow_unicode=True)

    links = [to_link(n) for n in final_nodes if to_link(n)]
    with open(f"{OUTPUT_DIR}/node_links.txt", 'w', encoding='utf-8') as f:
        f.write("\n".join(links))
    b64_str = base64.b64encode("\n".join(links).encode()).decode()
    with open(f"{OUTPUT_DIR}/subscribe_base64.txt", 'w', encoding='utf-8') as f:
        f.write(b64_str)

    print(f"🎉 任务结束! 最终导出节点: {len(final_nodes)}")
