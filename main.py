import json, urllib.request, yaml, os, ssl, warnings, re

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
        sn = rl.get('serverName') or ss.get('tlsSettings',{}).get('serverName') or d.get('sni','www.apple.com')
        return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","sn":sn,"pbk":rl.get('publicKey') or d.get('public_key'),"sid":rl.get('shortId') or d.get('short_id'),"net":ss.get('network','tcp')}
    except: return None

def handle_hy2(d):
    try:
        sr, u = str(d.get('server','')), d.get('auth') or d.get('auth_str') or d.get('password')
        if not sr or not u or d.get('protocol')=='freedom': return None
        h = sr.split(':')[0].replace('[','').replace(']','')
        pt = re.findall(r'\d+', sr.split(':')[1])[0] if ':' in sr else 443
        return {"s":h,"p":int(pt),"u":str(u),"t":"hysteria2","sn":d.get('sni') or d.get('server_name') or "www.apple.com"}
    except: return None

def handle_naive(d):
    try:
        m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d.get('proxy',''))
        if m: return {"u":m.group(1),"pass":m.group(2),"s":m.group(3),"p":int(m.group(4)),"t":"naive","sn":m.group(3)}
    except: return None

def handle_juicity(d):
    try:
        s, u, pw = d.get('server',''), d.get('uuid'), d.get('password')
        if not (s and u and pw): return None
        h, pt = s.rsplit(':', 1)
        return {"s":h,"p":int(pt),"u":str(u),"pw":str(pw),"t":"juicity","sn":d.get('sni',h),"cc":d.get('congestion_control','bbr')}
    except: return None

def handle_sq(d):
    try:
        ad = d.get('addr') or d.get('settings',{}).get('vnext',[{}])[0].get('address')
        u, pw = d.get('username') or d.get('auth'), d.get('password')
        if (d.get('type')!='shadowquic' and d.get('protocol')!='shadowquic') or not (ad and pw): return None
        h, pt = ad.rsplit(':', 1)
        return {"s":h,"p":int(pt),"u":str(u or "user"),"pw":str(pw),"t":"shadowquic","sn":d.get('server-name','www.yahoo.com'),"cc":d.get('congestion_control','bbr')}
    except: return None

def handle_mieru(d):
    try:
        usr, srv = d.get('user',{}), d.get('servers',[{}])[0]
        pts = srv.get('portBindings',[{}])[0]
        s, u, p = srv.get('ipAddress'), usr.get('name'), pts.get('port')
        if not (s and u and p): return None
        return {"s":str(s),"p":int(p),"u":str(u),"pw":str(usr.get('password')),"t":"mieru"}
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
                    n = handle_vless(d) or handle_hy2(d) or handle_juicity(d) or handle_naive(d) or handle_sq(d) or handle_mieru(d)
                    if n: nodes.append(n)
        except: continue
    uniq, seen, clash_px = [], set(), []
    for n in nodes:
        key = (n['s'], n['p'], n.get('u') or n.get('pw'))
        if key not in seen: uniq.append(n); seen.add(key)
    for i, n in enumerate(uniq):
        nm = f"🌐 {n['t'].upper()}_{i+1}_{n['s'][-5:]}"
        px = {"name": nm, "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        if n['t'] == 'vless':
            px.update({"type":"vless","uuid":n['u'],"tls":True,"servername":n['sn'],"network":n.get('net','tcp'),"udp":True})
            if n.get('pbk'): px.update({"reality-opts":{"public-key":n['pbk'],"short-id":n.get('sid','')}})
        elif n['t'] == 'hysteria2': px.update({"type":"hysteria2","password":n['u'],"sni":n['sn']})
        elif n['t'] == 'naive': px.update({"type":"http","username":n['u'],"password":n['pass'],"tls":True,"sni":n['sn'],"proxy-octet-stream":True})
        elif n['t'] == 'juicity': px.update({"type":"juicity","uuid":n['u'],"password":n['pw'],"sni":n['sn'],"congestion-control":n.get('cc','bbr')})
        elif n['t'] == 'shadowquic': px.update({"type":"shadowquic","username":n['u'],"password":n['pw'],"sni":n['sn'],"congestion-control":n.get('cc','bbr')})
        elif n['t'] == 'mieru': px.update({"type":"socks5","username":n['u'],"password":n['pw']})
        clash_px.append(px)
    conf = {"proxies": clash_px, "proxy-groups": [{"name": "🚀 🚀", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300}, {"name": "🔰 🔰", "type": "select", "proxies": ["🚀 🚀"] + [p['name'] for p in clash_px]}], "rules": ["MATCH,🔰 🔰"]}
    with open(f"{OUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    print(f"✅ Nodes: {len(clash_px)}")

if __name__ == "__main__":
    main()
