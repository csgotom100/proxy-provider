import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")

BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')

os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    try:
        # --- 1. NaiveProxy 逻辑 ---
        if 'proxy' in d and 'https://' in str(d['proxy']):
            m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d['proxy'])
            if m:
                return {"t": "naive", "u": m.group(1), "pw": m.group(2), "s": m.group(3), "p": int(m.group(4)), "sn": m.group(3)}

        # --- 2. Hysteria2 逻辑 (严格适配提供的 JSON) ---
        # 识别特征：包含 bandwidth 或 quic 或 socks5 且 server 存在
        if 'bandwidth' in d or 'quic' in d or str(d.get('type','')).lower() == 'hysteria2':
            s_raw = d.get('server') or d.get('add')
            if not s_raw: return None
            
            # 处理带端口范围的 server: "ip:port,port-port" -> 提取第一个端口
            s_part = str(s_raw).split(',')[0]
            host = s_part.split(':')[0].replace('[','').replace(']','')
            port = s_part.split(':')[1] if ':' in s_part else d.get('server_port', 443)
            
            u = d.get('auth') or d.get('password') or d.get('auth_str')
            
            # 深入 tls 字典获取参数
            tls = d.get('tls', {})
            sni = tls.get('sni') or d.get('sni') or 'apple.com'
            is_insecure = 1 if tls.get('insecure') is True else 0
            
            return {
                "t": "hysteria2", "s": host, "p": int(port), "u": str(u),
                "sn": sni, "insecure": is_insecure
            }

        # --- 3. VLESS 逻辑 (适配 sing-box 风格) ---
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        if 'vless' in ptype:
            s = d.get('server') or d.get('add')
            p = d.get('server_port') or d.get('port')
            u = d.get('uuid') or d.get('id')
            if not (s and u): return None
            
            sec, sn, pbk, sid, fp = 'none', None, None, None, None
            tls = d.get('tls', {})
            if tls and tls.get('enabled'):
                sec, sn = 'tls', tls.get('server_name')
                fp = tls.get('utls', {}).get('fingerprint')
                ry = tls.get('reality', {})
                if ry and ry.get('enabled'):
                    sec, pbk, sid = 'reality', ry.get('public_key'), ry.get('short_id')
            
            ss = d.get('streamSettings', {})
            net = d.get('transport', {}).get('type') or ss.get('network') or d.get('net', 'tcp')
            if ss:
                sec = ss.get('security') or sec
                rl = ss.get('realitySettings')
                if rl:
                    sn, pbk, sid, fp = rl.get('serverName'), rl.get('publicKey'), rl.get('shortId'), rl.get('fingerprint')

            return {"t": "vless", "s": str(s), "p": int(p), "u": str(u), "net": net, "sec": sec, "sn": sn, "pbk": pbk, "sid": sid, "fp": fp}
            
    except: return None
    return None

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
    
    all_nodes = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if '{' in raw else yaml.safe_load(raw)
                for d in find_dicts(data):
                    node = parse_node(d)
                    if node: all_nodes.append(node)
        except: continue

    unique_nodes, seen = [], set()
    for n in all_nodes:
        key = (n['s'], n['p'], n.get('u') or n.get('pw'))
        if key not in seen: unique_nodes.append(n); seen.add(key)

    clash_proxies, v2_links = [], []
    for i, n in enumerate(unique_nodes):
        node_name = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        px = {"name": node_name, "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'vless':
            px.update({"type": "vless", "uuid": n['u'], "udp": True, "network": n.get('net', 'tcp')})
            if n['sec'] in ['tls', 'reality']:
                px["tls"] = True
                if n['sn']: px["servername"] = n['sn']
                if n['fp']: px["client-fingerprint"] = n['fp']
            if n['sec'] == 'reality' and n['pbk']:
                px["reality-opts"] = {"public-key": n['pbk'], "short-id": n['sid'] or ""}
            l = f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security={n['sec']}&type={n.get('net','tcp')}"
            if n['sn']: l += f"&sni={n['sn']}"
            if n['fp']: l += f"&fp={n['fp']}"
            if n['pbk']: l += f"&pbk={n['pbk']}&sid={n['sid'] or ''}"
            v2_links.append(f"{l}#{node_name}")
        
        elif n['t'] == 'hysteria2':
            # 严格按照正确链接格式生成
            px.update({"type": "hysteria2", "password": n['u'], "sni": n['sn']})
            link = f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure={n['insecure']}&allowInsecure={n['insecure']}"
            v2_links.append(f"{link}#{node_name}")
        
        elif n['t'] == 'naive':
            px.update({"type": "http", "username": n['u'], "password": n['pw'], "tls": True, "sni": n['sn'], "proxy-octet-stream": True})
            v2_links.append(f"http://{n['u']}:{n['pw']}@{n['s']}:{n['p']}#{node_name}")

        clash_proxies.append(px)

    if not clash_proxies: return

    conf = {"proxies": clash_proxies, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [p['name'] for p in clash_proxies] + ["DIRECT"]}, {"name": "⚡ 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300}], "rules": ["MATCH,🚀 节点选择"]}

    with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f:
        f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(v2_links).encode()).decode())

if __name__ == "__main__":
    main()
