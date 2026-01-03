import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
OUT_DIR, MANUAL_FILE = './sub', './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def handle_vless(d):
    try:
        # 获取基础连接信息
        if 'vnext' in d.get('settings', {}):
            v = d['settings']['vnext'][0]
            s, p, u = v.get('address'), v.get('port'), v['users'][0].get('id')
        else:
            s, p, u = d.get('server') or d.get('add'), d.get('server_port') or d.get('port'), d.get('uuid') or d.get('id')
        
        if not (s and u): return None
        
        # 提取传输层和安全层配置 (Strictly from JSON)
        ss = d.get('streamSettings', {})
        net = ss.get('network', d.get('net', 'tcp'))
        sec = ss.get('security', d.get('security', 'none'))
        
        node = {
            "s": str(s), "p": int(p), "u": str(u), "t": "vless",
            "net": net, "sec": sec, "sn": None, "pbk": None, "sid": None,
            "path": None, "host": None, "fp": None
        }

        # 处理 Reality 逻辑 (仅当 JSON 存在时提取)
        rl = ss.get('realitySettings', d.get('reality'))
        if rl:
            node["sn"] = rl.get('serverName')
            node["pbk"] = rl.get('publicKey')
            node["sid"] = rl.get('shortId')
            node["fp"] = rl.get('fingerprint')

        # 处理 TLS/SNI 逻辑 (如果不是 Reality 而是普通 TLS)
        tls = ss.get('tlsSettings', d.get('tls'))
        if tls and not node["sn"]:
            node["sn"] = tls.get('serverName') or d.get('sni')

        # 处理传输层设置 (WS/GRPC/XHTTP/H2)
        ts = ss.get(f"{net}Settings")
        if ts:
            node["path"] = ts.get('path') or d.get('path')
            h_obj = ts.get('headers', {})
            node["host"] = h_obj.get('Host') or d.get('host')

        return node
    except: return None

def handle_hy2(d):
    try:
        sr, u = str(d.get('server','')), d.get('auth') or d.get('auth_str') or d.get('password')
        if not sr or not u or d.get('protocol')=='freedom': return None
        h = sr.split(':')[0].replace('[','').replace(']','')
        pt = re.findall(r'\d+', sr.split(':')[1])[0] if ':' in sr else 443
        return {"s":h,"p":int(pt),"u":str(u),"t":"hysteria2","sn":d.get('sni') or d.get('server_name')}
    except: return None

def handle_naive(d):
    try:
        m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d.get('proxy',''))
        if m: return {"u":m.group(1),"pw":m.group(2),"s":m.group(3),"p":int(m.group(4)),"t":"naive","sn":m.group(3)}
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
                    n = handle_vless(d) or handle_hy2(d) or handle_naive(d)
                    if n: nodes.append(n)
        except: continue
    
    uniq, seen, clash_px, v2_links = [], set(), [], []
    for n in nodes:
        key = (n['s'], n['p'], n.get('u') or n.get('pw'))
        if key not in seen: uniq.append(n); seen.add(key)

    for i, n in enumerate(uniq):
        nm = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        px = {"name": nm, "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'vless':
            px.update({"type":"vless","uuid":n['u'],"udp":True,"network":n['net']})
            if n['sec'] in ['tls', 'reality']:
                px["tls"] = True
                if n['sn']: px["servername"] = n['sn']
                if n['fp']: px["client-fingerprint"] = n['fp']
            if n['sec'] == 'reality' and n['pbk']:
                px["reality-opts"] = {"public-key": n['pbk'], "short-id": n['sid'] or ""}
            if n['net'] in ['ws', 'grpc', 'xhttp']:
                px[f"{n['net']}-opts"] = {k: v for k, v in {"path": n['path'], "headers": {"Host": n['host']} if n['host'] else None}.items() if v}
            
            # 生成 v2rayN 链接 (严格匹配)
            link = f"vless://{n['u']}@{n['s']}:{n['p']}?type={n['net']}&security={n['sec']}"
            if n['sn']: link += f"&sni={n['sn']}"
            if n['fp']: link += f"&fp={n['fp']}"
            if n['pbk']: link += f"&pbk={n['pbk']}&sid={n['sid'] or ''}"
            if n['path']: link += f"&path={n['path']}"
            v2_links.append(f"{link}#{nm}")
        
        elif n['t'] == 'hysteria2':
            px.update({"type":"hysteria2","password":n['u'],"sni":n['sn']})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn'] or ''}#{nm}")
        
        elif n['t'] == 'naive':
            px.update({"type":"http","username":n['u'],"password":n['pw'],"tls":True,"sni":n['sn'],"proxy-octet-stream":True})
            v2_links.append(f"http://{n['u']}:{n['pw']}@{n['s']}:{n['p']}#{nm}")

        clash_px.append(px)

    conf = {"proxies": clash_px, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [p['name'] for p in clash_px] + ["DIRECT"]}, {"name": "⚡ 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300}], "rules": ["MATCH,🚀 节点选择"]}
    with open(f"{OUT_DIR}/clash.yaml",'w',encoding='utf-8') as f: yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    with open(f"{OUT_DIR}/node.txt",'w',encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(f"{OUT_DIR}/sub.txt",'w',encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())
    print(f"✅ Success: {len(clash_px)}")

if __name__ == "__main__": main()
