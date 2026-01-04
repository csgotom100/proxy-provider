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

        # --- 2. Hysteria2 (适配 JSON 和 Clash YAML) ---
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        if 'hysteria2' in ptype or 'quic' in d:
            s = d.get('server') or d.get('add')
            if not s: return None
            s_part = str(s).split(',')[0]
            host, port = s_part.split(':')[0].replace('[','').replace(']',''), s_part.split(':')[1] if ':' in s_part else d.get('port', 443)
            u = d.get('auth') or d.get('password') or d.get('auth_str')
            tls = d.get('tls', {})
            return {
                "t": "hysteria2", "s": host, "p": int(port), "u": str(u), 
                "sn": tls.get('sni') or d.get('sni') or d.get('servername'), 
                "insecure": 1 if (tls.get('insecure') or d.get('skip-cert-verify')) else 0
            }

        # --- 3. VLESS (核心：参数像素级透传) ---
        if 'vless' in ptype:
            s, p, u = d.get('server') or d.get('add'), d.get('port') or d.get('server_port'), d.get('uuid') or d.get('id')
            if not (s and u): return None
            
            # 基础透传
            p_list = {"encryption": d.get("encryption", "none"), "flow": d.get("flow"), "packetEncoding": d.get("packet_encoding") or d.get("packet-addr")}
            sec, sn, pbk, sid, fp, net = 'none', None, None, None, None, d.get('network', 'tcp')
            
            # 处理 sing-box 嵌套
            tls = d.get('tls', {})
            if isinstance(tls, dict) and tls.get('enabled'):
                sec = 'reality' if tls.get('reality', {}).get('enabled') else 'tls'
                sn, fp = tls.get('server_name'), tls.get('utls', {}).get('fingerprint')
                ry = tls.get('reality', {})
                if ry: pbk, sid = ry.get('public_key'), ry.get('short_id')
            
            # 处理 Clash/Xray 扁平结构
            if d.get('tls') is True or d.get('security'):
                sec = d.get('security') or 'tls'
                sn = d.get('servername') or d.get('sni')
                fp = d.get('client-fingerprint') or d.get('fp')
                if sec == 'reality' or 'reality-opts' in d:
                    sec = 'reality'
                    ro = d.get('reality-opts', {})
                    pbk = ro.get('public-key') or d.get('pbk')
                    sid = ro.get('short-id') or d.get('sid')

            final_p = {k: v for k, v in p_list.items() if v}
            final_p.update({"security": sec, "type": net, "sni": sn, "fp": fp, "pbk": pbk, "sid": sid})
            return {"t":"vless","s":str(s),"p":int(p),"u":str(u),"params": {k: v for k, v in final_p.items() if v}}
    except: return None

def find_dicts(obj):
    """递归查找所有包含节点信息的字典，支持 Clash proxies 列表"""
    if isinstance(obj, dict):
        yield obj
        if 'proxies' in obj and isinstance(obj['proxies'], list):
            for item in obj['proxies']: yield from find_dicts(item)
        for v in obj.values(): yield from find_dicts(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_dicts(i)

def main():
    if not os.path.exists(MANUAL_FILE): return
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
        urls = re.findall(r'https?://[^\s\'"\[\],]+', content)
    
    nodes = []
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
        nm = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        if n['t'] == 'vless':
            p = n['params']
            px = {"name": nm, "type": "vless", "server": n['s'], "port": n['p'], "uuid": n['u'], "tls": True, "skip-cert-verify": True, "network": p.get("type", "tcp")}
            if p.get("sni"): px["servername"] = p["sni"]
            if p.get("fp"): px["client-fingerprint"] = p["fp"]
            if p.get("flow"): px["flow"] = p["flow"]
            if p.get("security") == "reality": px["reality-opts"] = {"public-key": p.get("pbk"), "short-id": p.get("sid", "")}
            clash_proxies.append(px)
            query = "&".join([f"{k}={v}" for k, v in p.items()])
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?{query}#{nm}")
        elif n['t'] == 'hysteria2':
            clash_proxies.append({"name": nm, "type": "hysteria2", "server": n['s'], "port": n['p'], "password": n['u'], "sni": n.get('sn'), "skip-cert-verify": True})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n.get('sn','')}&insecure={n['insecure']}&allowInsecure={n['insecure']}#{nm}")
        elif n['t'] == 'naive':
            # Clash 不添加 Naive 节点，仅保留在 node.txt
            v2_links.append(f"{n['raw']}#{nm}")
            pass 

    if not v2_links: return
    # 写入 Clash
    if clash_proxies:
        with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
            yaml.dump({"proxies": clash_proxies, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [p['name'] for p in clash_proxies] + ["DIRECT"]}, {"name": "⚡ 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300}], "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)
    # 写入链接文件
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())

if __name__ == "__main__":
    main()
