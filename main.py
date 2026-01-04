import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    try:
        # --- 1. NaiveProxy (严格保持原始 https 字符串) ---
        if 'proxy' in d and str(d['proxy']).startswith('https://'):
            p_str = d['proxy']
            m = re.search(r'@([^:]+):(\d+)', p_str)
            if m:
                u_p = re.search(r'https://([^:]+):([^@]+)@', p_str).groups()
                return {"t": "naive", "raw": p_str, "s": m.group(1), "p": int(m.group(2)), "auth": u_p}

        # --- 2. Hysteria2 (按 JSON 提取 TLS 参数) ---
        if 'bandwidth' in d or 'quic' in d or str(d.get('type','')).lower() == 'hysteria2':
            s_raw = d.get('server', '')
            if not s_raw: return None
            s_part = str(s_raw).split(',')[0]
            host, port = s_part.split(':')[0].replace('[','').replace(']',''), s_part.split(':')[1] if ':' in s_part else 443
            u = d.get('auth') or d.get('password') or d.get('auth_str')
            tls = d.get('tls', {})
            return {"t": "hysteria2", "s": host, "p": int(port), "u": str(u), "sn": tls.get('sni'), "insecure": 1 if tls.get('insecure') else 0}

        # --- 3. VLESS (参数严格遵循 JSON) ---
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        if 'vless' in ptype:
            s, p, u = d.get('server') or d.get('add'), d.get('server_port') or d.get('port'), d.get('uuid') or d.get('id')
            if not (s and u): return None
            
            # 基础参数
            params = {
                "encryption": d.get("encryption", "none"),
                "flow": d.get("flow"),
                "packetEncoding": d.get("packet_encoding")
            }
            
            # 安全与传输层
            sec, sn, pbk, sid, fp, net = 'none', None, None, None, None, 'tcp'
            
            # sing-box 风格解析
            tls = d.get('tls', {})
            if tls and tls.get('enabled'):
                sec = 'reality' if tls.get('reality', {}).get('enabled') else 'tls'
                sn = tls.get('server_name')
                fp = tls.get('utls', {}).get('fingerprint')
                ry = tls.get('reality', {})
                if ry:
                    pbk, sid = ry.get('public_key'), ry.get('short_id')
            
            # xray 风格解析
            ss = d.get('streamSettings', {})
            if ss:
                net = ss.get('network') or d.get('transport', {}).get('type') or 'tcp'
                sec = ss.get('security') or sec
                rl = ss.get('realitySettings')
                if rl:
                    sn, pbk, sid, fp = rl.get('serverName'), rl.get('publicKey'), rl.get('shortId'), rl.get('fingerprint')

            # 组装参数字典 (过滤 None)
            final_params = {k: v for k, v in params.items() if v}
            final_params.update({
                "security": sec,
                "type": net,
                "sni": sn,
                "fp": fp,
                "pbk": pbk,
                "sid": sid
            })
            
            return {"t":"vless","s":str(s),"p":int(p),"u":str(u),"params": {k: v for k, v in final_params.items() if v}}
            
    except: return None

def find_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values(): yield from find_dicts(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_dicts(i)

def main():
    if not os.path.exists(MANUAL_FILE): return
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    nodes = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if '{' in raw else yaml.safe_load(raw)
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
        
        if n['t'] == 'vless':
            # Clash 逻辑
            p = n['params']
            px = {"name": nm, "type": "vless", "server": n['s'], "port": n['p'], "uuid": n['u'], "tls": True, "skip-cert-verify": True}
            px["network"] = p.get("type", "tcp")
            if p.get("sni"): px["servername"] = p["sni"]
            if p.get("fp"): px["client-fingerprint"] = p["fp"]
            if p.get("flow"): px["flow"] = p["flow"]
            if p.get("security") == "reality":
                px["reality-opts"] = {"public-key": p.get("pbk"), "short-id": p.get("sid", "")}
            clash_proxies.append(px)
            
            # v2ray 链接拼接 (严格按提取到的参数列表)
            query = "&".join([f"{k}={v}" for k, v in p.items()])
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?{query}#{nm}")
            
        elif n['t'] == 'hysteria2':
            clash_proxies.append({"name": nm, "type": "hysteria2", "server": n['s'], "port": n['p'], "password": n['u'], "sni": n.get('sn'), "skip-cert-verify": True})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n.get('sn','')}&insecure={n['insecure']}&allowInsecure={n['insecure']}#{nm}")
            
        elif n['t'] == 'naive':
            clash_proxies.append({"name": nm, "type": "http", "server": n['s'], "port": n['p'], "username": n['auth'][0], "password": n['auth'][1], "tls": True, "sni": n['s'], "skip-cert-verify": True})
            v2_links.append(f"{n['raw']}#{nm}")

    if not clash_proxies: return
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f: f.write("\n".join(v2_links))
    # ... (Clash 和 sub.txt 写入逻辑保持不变)
