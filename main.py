import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    try:
        # 获取类型并标准化
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        
        # --- 1. Hysteria2 (精准匹配你贴出的格式) ---
        if 'hysteria2' in ptype:
            # 优先从 'server' 字段获取地址，如果没有则看 'add'
            host = d.get('server') or d.get('add')
            if not host: return None
            
            # 提取密码：Clash 用 password, sing-box 用 auth
            pw = d.get('password') or d.get('auth') or d.get('auth_str')
            if not pw: return None
            
            return {
                "t": "hysteria2", 
                "s": str(host).replace('[','').replace(']',''), 
                "p": int(d.get('port', 443)), 
                "u": str(pw), 
                "sn": d.get('sni') or d.get('servername'), 
                "insecure": 1 if (d.get('skip-cert-verify') or d.get('insecure')) else 0
            }

        # --- 2. VLESS ---
        if 'vless' in ptype:
            s, p, u = d.get('server') or d.get('add'), d.get('port'), d.get('uuid') or d.get('id')
            if not (s and u): return None
            
            sec, sn, pbk, sid, fp, net = 'none', None, None, None, None, d.get('network', 'tcp')
            ro = d.get('reality-opts', {})
            if ro:
                sec = 'reality'
                pbk = ro.get('public-key')
                sid = ro.get('short-id')
            
            sn = d.get('servername') or d.get('sni')
            fp = d.get('client-fingerprint') or d.get('fp')
            if d.get('tls') is True and sec == 'none': sec = 'tls'

            params = {"security": sec, "sni": sn, "fp": fp, "pbk": pbk, "sid": sid, "type": net, "flow": d.get("flow")}
            return {"t":"vless","s":str(s),"p":int(p),"u":str(u),"params": {k: v for k, v in params.items() if v}}

        # --- 3. NaiveProxy ---
        if 'proxy' in d and str(d['proxy']).startswith('https://'):
            p_str = d['proxy']
            m = re.search(r'@([^:]+):(\d+)', p_str)
            if m: return {"t": "naive", "raw": p_str, "s": m.group(1), "p": int(m.group(2))}

    except: return None

def find_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        # 如果是 Clash 配置文件，重点扫描 proxies 列表
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
    # 核心：先尝试将 manual_json.txt 全文直接作为 YAML 解析 (处理你贴进去的 Clash 配置)
    try:
        data = yaml.safe_load(content)
        if data:
            for d in find_dicts(data):
                n = parse_node(d)
                if n: nodes.append(n)
    except Exception as e:
        print(f"YAML Text Parse Skip: {e}")

    # 再处理文件中包含的 URL
    urls = re.findall(r'https?://[^\s\'"\[\],]+', content)
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                try: data = json.loads(raw)
                except: data = yaml.safe_load(raw)
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
        host_tag = n['s'].split('.')[-1] if '.' in n['s'] else 'v6'
        nm = f"{i+1:02d}_{n['t'].upper()}_{host_tag}"
        
        if n['t'] == 'hysteria2':
            # 导出为 Clash 格式
            clash_proxies.append({"name": nm, "type": "hysteria2", "server": n['s'], "port": n['p'], "password": n['u'], "sni": n.get('sn'), "skip-cert-verify": True})
            # 导出为链接格式 (auth@server:port)
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n.get('sn','')}&insecure=1#{nm}")
        elif n['t'] == 'vless':
            p = n['params']
            px = {"name": nm, "type": "vless", "server": n['s'], "port": n['p'], "uuid": n['u'], "tls": True, "skip-cert-verify": True, "network": p.get("type", "tcp")}
            if p.get("sni"): px["servername"] = p["sni"]
            if p.get("security") == "reality": px["reality-opts"] = {"public-key": p.get("pbk"), "short-id": p.get("sid", "")}
            clash_proxies.append(px)
            query = "&".join([f"{k}={v}" for k, v in p.items() if v])
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?{query}#{nm}")
        elif n['t'] == 'naive':
            v2_links.append(f"{n['raw']}#{nm}")

    if not v2_links: return
    if clash_proxies:
        conf = {"proxies": clash_proxies, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [px['name'] for px in clash_proxies] + ["DIRECT"]}], "rules": ["MATCH,🚀 节点选择"]}
        with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
            yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
            
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())

if __name__ == "__main__":
    main()
