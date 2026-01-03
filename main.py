import yaml, json, urllib.request, socket, time, re, base64, os, urllib.parse
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# --- 配置 ---
TIMEOUT = 10.0           
MAX_THREADS = 40
SOURCE_FILE = './urls/manual_json.txt'
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)
GEO_CACHE = {}

def get_location(ip):
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
        with urllib.request.urlopen(url, timeout=3) as res:
            data = json.loads(res.read().decode())
            loc = data.get('country', '未知')
            GEO_CACHE[ip] = loc
            return loc
    except: return "未知"

def decode_base64(data):
    try:
        data = data.replace('-', '+').replace('_', '/')
        missing_padding = len(data) % 4
        if missing_padding: data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except: return ""

def extract_all_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(extract_all_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(extract_all_dicts(i))
    return res

def parse_remote(url):
    nodes = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=12) as res:
            content = res.read().decode('utf-8', errors='ignore').strip()
            
            # --- 1. 处理 Base64 订阅内容 ---
            if not (content.startswith('{') or "proxies" in content or "outbounds" in content):
                decoded = decode_base64(content)
                if decoded:
                    for line in decoded.splitlines():
                        if "://" in line: nodes.append({"raw_uri": line.strip()})
            
            # --- 2. 处理 JSON/YAML 结构化内容 ---
            data = json.loads(content) if (content.startswith('{') or content.startswith('[')) else yaml.safe_load(content)
            if data:
                for item in extract_all_dicts(data):
                    # 寻找服务器
                    srv = item.get('server') or item.get('add') or item.get('address') or item.get('ipAddress')
                    # 寻找端口 (增加更多变体)
                    prt = item.get('port') or item.get('server_port') or item.get('listen_port') or item.get('port_num')
                    if not srv or not prt or str(srv).startswith('127.'): continue

                    # 识别协议
                    p_type = str(item.get('type', '')).lower()
                    secret = item.get('password') or item.get('uuid') or item.get('auth') or item.get('id') or item.get('auth-str')
                    
                    if 'auth' in item or 'hy2' in p_type: ntype = 'hysteria2'
                    elif 'uuid' in item or 'vless' in p_type or 'id' in item: ntype = 'vless'
                    elif 'cipher' in item or 'method' in item: ntype = 'ss'
                    elif 'socks' in p_type: ntype = 'socks5'
                    else: continue

                    if not secret: continue

                    node = {
                        "server": str(srv),
                        "port": int(str(prt).split(',')[0].split('-')[0]),
                        "type": ntype,
                        "sni": item.get('sni') or item.get('server_name') or item.get('serverName'),
                        "skip-cert-verify": True
                    }
                    if ntype == 'vless': node["uuid"] = secret
                    else: node["password"] = secret

                    # Reality
                    ry = item.get('reality') or item.get('reality-opts') or item.get('tls', {}).get('reality')
                    if ry and isinstance(ry, dict):
                        node["reality-opts"] = {
                            "public-key": ry.get('public-key') or ry.get('publicKey') or ry.get('public_key'),
                            "short-id": ry.get('short-id') or ry.get('shortId') or ry.get('short_id')
                        }
                    nodes.append(node)
    except: pass
    return nodes

def to_link(p):
    """根据字典生成 URI 链接"""
    if "raw_uri" in p: return p["raw_uri"]
    try:
        name = urllib.parse.quote(p.get('name', 'Proxy'))
        s, prt = p['server'], p['port']
        if p['type'] == 'hysteria2':
            return f"hysteria2://{p['password']}@{s}:{prt}?insecure=1&sni={p.get('sni','')}#{name}"
        if p['type'] == 'vless':
            link = f"vless://{p['uuid']}@{s}:{prt}?encryption=none&security=reality&sni={p.get('sni','')}"
            if p.get('reality-opts'):
                link += f"&pbk={p['reality-opts']['public-key']}&sid={p['reality-opts']['short-id']}"
            return f"{link}#{name}"
        if p['type'] == 'ss':
            return f"ss://{p['server']}:{p['port']}#{name}"
    except: return None

def main():
    # 核心源列表
    urls = [
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
        "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    ]
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r') as f:
            urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))

    all_raw = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
        for nodes in exe.map(parse_remote, urls):
            all_raw.extend(nodes)

    # 去重 & 地域命名
    final_nodes = []
    seen = set()
    for n in all_raw:
        # 如果是 URI 格式则特殊处理去重
        srv_key = n.get('server') or n.get('raw_uri')
        if srv_key not in seen:
            if 'server' in n:
                loc = get_location(n['server'])
                n['name'] = f"[{loc}] {n['type'].upper()}_{str(n['server'])[-4:]}"
            final_nodes.append(n)
            seen.add(srv_key)

    # --- 输出 1: Clash YAML ---
    clash_nodes = [n for n in final_nodes if 'server' in n]
    clash_config = {
        "proxies": clash_nodes,
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [n['name'] for n in clash_nodes]}],
        "rules": ["MATCH,PROXY"]
    }
    with open(f"{OUTPUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)

    # --- 输出 2: 明文链接 (node_links.txt) ---
    links = [to_link(n) for n in final_nodes if to_link(n)]
    with open(f"{OUTPUT_DIR}/node_links.txt", 'w', encoding='utf-8') as f:
        f.write("\n".join(links))

    # --- 输出 3: Base64 订阅 (sub.txt) ---
    with open(f"{OUTPUT_DIR}/sub.txt", 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())
    
    print(f"✅ 任务完成! 抓取节点: {len(final_nodes)}")

if __name__ == "__main__":
    main()
