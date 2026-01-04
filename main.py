import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    try:
        # 1. 提取类型
        ptype = str(d.get('type', '')).lower()
        
        # --- Hysteria2 专项提取 ---
        if 'hysteria2' in ptype:
            # 直接锁定你提供的 Clash 字段名
            host = d.get('server')
            port = d.get('port')
            pw = d.get('password') # 重点：对应你配置里的 password
            if not (host and pw): return None
            
            return {
                "t": "hysteria2",
                "s": str(host).replace('[','').replace(']',''),
                "p": int(port),
                "u": str(pw),
                "sn": d.get('sni') or d.get('servername'),
                "insecure": 1 if d.get('skip-cert-verify') else 0
            }

        # --- VLESS 专项提取 ---
        if 'vless' in ptype:
            host = d.get('server')
            port = d.get('port')
            uuid = d.get('uuid')
            if not (host and uuid): return None
            
            # 提取 Reality 参数
            ro = d.get('reality-opts', {})
            params = {
                "security": "reality" if ro else "tls",
                "sni": d.get('servername') or d.get('sni'),
                "fp": d.get('client-fingerprint'),
                "pbk": ro.get('public-key'),
                "sid": ro.get('short-id'),
                "type": d.get('network', 'tcp'),
                "flow": d.get('flow')
            }
            return {"t": "vless", "s": str(host), "p": int(port), "u": str(uuid), "params": {k: v for k, v in params.items() if v}}

        # --- Naive 保持原样 ---
        if 'proxy' in d and str(d['proxy']).startswith('https://'):
            return {"t": "naive", "raw": d['proxy'], "s": "naive_node", "p": 443}

    except: return None

def find_dicts(obj):
    """确保能遍历到 proxies 列表里的每一个字典"""
    if isinstance(obj, dict):
        if 'type' in obj: yield obj # 只要有 type 字段就尝试解析
        if 'proxies' in obj and isinstance(obj['proxies'], list):
            for item in obj['proxies']: yield from find_dicts(item)
        for v in obj.values(): yield from find_dicts(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_dicts(i)

def main():
    if not os.path.exists(MANUAL_FILE): return
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    
    nodes = []
    # 尝试解析 manual_json.txt
    try:
        data = yaml.safe_load(content)
        for d in find_dicts(data):
            n = parse_node(d)
            if n: nodes.append(n)
    except: pass

    # 尝试解析 URL
    urls = re.findall(r'https?://[^\s\'"\[\],]+', content)
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = yaml.safe_load(raw)
                for d in find_dicts(data):
                    n = parse_node(d)
                    if n: nodes.append(n)
        except: continue

    unique_nodes, seen = [], set()
    for n in nodes:
        key = (n['s'], n['p'], n.get('u', n.get('raw', '')))
        if key not in seen: unique_nodes.append(n); seen.add(key)

    clash_proxies, v2_links = [], []
    for i, n in enumerate(unique_nodes):
        nm = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        
        if n['t'] == 'hysteria2':
            # 严格按照你要求的格式输出
            clash_proxies.append({
                "name": nm, "type": "hysteria2", "server": n['s'], "port": n['p'], 
                "password": n['u'], "sni": n['sn'], "skip-cert-verify": True
            })
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure=1#{nm}")
        elif n['t'] == 'vless':
            p = n['params']
            px = {"name": nm, "type": "vless", "server": n['s'], "port": n['p'], "uuid": n['u'], "tls": True, "skip-cert-verify": True}
            if p.get("sni"): px["servername"] = p["sni"]
            if p.get("security") == "reality": px["reality-opts"] = {"public-key": p["pbk"], "short-id": p.get("sid", "")}
            clash_proxies.append(px)
            query = "&".join([f"{k}={v}" for k, v in p.items()])
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?{query}#{nm}")
        elif n['t'] == 'naive':
            v2_links.append(f"{n['raw']}#{nm}")

    if not v2_links: return
    # 写入文件
    if clash_proxies:
        with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
            yaml.dump({"proxies": clash_proxies, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [px['name'] for px in clash_proxies] + ["DIRECT"]}], "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)
    
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())

if __name__ == "__main__":
    main()
