import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
OUT_DIR, MANUAL_FILE = './sub', './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def handle_vless(d):
    try:
        if 'vnext' in d.get('settings', {}):
            v = d['settings']['vnext'][0]
            s, p, u = v.get('address'), v.get('port'), v['users'][0].get('id')
        else:
            s, p, u = d.get('server') or d.get('add'), d.get('server_port') or d.get('port'), d.get('uuid') or d.get('id')
        if not (s and u): return None
        ss = d.get('streamSettings', {})
        rl = ss.get('realitySettings', d.get('reality', {}))
        sn = rl.get('serverName') or ss.get('tlsSettings',{}).get('serverName') or d.get('sni','itunes.apple.com')
        return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","sn":sn,"pbk":rl.get('publicKey') or d.get('public_key'),"sid":rl.get('shortId') or d.get('short_id',""),"net":ss.get('network', d.get('net','tcp'))}
    except: return None

def handle_hy2(d):
    try:
        sr, u = str(d.get('server','')), d.get('auth') or d.get('auth_str') or d.get('password')
        if not sr or not u or d.get('protocol')=='freedom': return None
        h = sr.split(':')[0].replace('[','').replace(']','')
        pt = re.findall(r'\d+', sr.split(':')[1])[0] if ':' in sr else 443
        return {"s":h,"p":int(pt),"u":str(u),"t":"hysteria2","sn":d.get('sni') or d.get('server_name') or "apple.com"}
    except: return None

def handle_naive(d):
    try:
        # 匹配 Alvin 源中常见的 NaiveProxy 格式
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
                    # 关键修复点：依次尝试解析所有协议
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
            px.update({"type":"vless","uuid":n['u'],"tls":True,"udp":True,"servername":n['sn'],"network":n['net'],"client-fingerprint":"chrome"})
            if n.get('pbk'): px.update({"reality-opts":{"public-key":n['pbk'],"short-id":n['sid']}})
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security=reality&sni={n['sn']}&fp=chrome&pbk={n.get('pbk','')}&sid={n.get('sid','')}&type={n['net']}#{nm}")
        
        elif n['t'] == 'hysteria2':
            px.update({"type":"hysteria2","password":n['u'],"sni":n['sn']})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure=1#{nm}")
        
        elif n['t'] == 'naive':
            # NaiveProxy 在 Clash 中表现为 type: http
            px.update({"type":"http","username":n['u'],"password":n['pw'],"tls":True,"sni":n['sn'],"proxy-octet-stream":True})
            # 在 node.txt 中以 http:// 格式保存，v2rayN 可识别
            v2_links.append(f"http://{n['u']}:{n['pw']}@{n['s']}:{n['p']}#{nm}")

        clash_px.append(px)

    conf = {
        "proxies": clash_px,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [p['name'] for p in clash_px] + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🌍 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
            {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["🚀 节点选择", "DIRECT"]}
        ],
        "rules": ["GEOIP,LAN,DIRECT", "GEOIP,CN,🌍 全球直连", "MATCH,🐟 漏网之鱼"]
    }

    with open(f"{OUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    with open(f"{OUT_DIR}/node.txt", 'w', encoding='utf-8') as f:
        f.write("\n".join(v2_links))
    with open(f"{OUT_DIR}/sub.txt", 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(v2_links).encode()).decode())

    print(f"✅ 处理完成! 节点总数: {len(clash_px)} (包含 Naive: {len([x for x in uniq if x['t']=='naive'])})")

if __name__ == "__main__":
    main()
