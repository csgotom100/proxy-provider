import json, urllib.request, yaml, os, ssl, warnings, re

warnings.filterwarnings("ignore")
OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    try:
        ip = ip.replace('[','').replace(']','')
        if not re.match(r'^\d', ip) and not ':' in ip: return "🏳️"
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3) as r:
            c = json.loads(r.read().decode()).get('countryCode', 'UN')
            return "".join(chr(ord(i) + 127397) for i in c.upper())
    except: return "🏳️"

def handle_vless_reality(d):
    try:
        s, p, u = d.get('server') or d.get('add'), d.get('server_port') or d.get('port'), d.get('uuid') or d.get('id')
        if not (s and u): return None
        tls = d.get('tls', {})
        real = tls.get('reality', {}) if isinstance(tls, dict) else {}
        return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","sn":tls.get('server_name') if isinstance(tls, dict) else d.get('sni',''),"pbk":real.get('public_key'),"sid":real.get('short_id')}
    except: return None

def handle_hy2_native(d):
    try:
        s_raw, u = str(d.get('server', '')), d.get('auth') or d.get('auth_str') or d.get('password')
        if not s_raw or not u: return None
        host = s_raw.split(':')[0].replace('[','').replace(']','')
        port = re.findall(r'\d+', s_raw.split(':')[1])[0] if ':' in s_raw else 443
        tls = d.get('tls', {})
        sn = d.get('sni') or d.get('server_name')
        if isinstance(tls, dict): sn = tls.get('sni') or tls.get('server_name') or sn
        return {"s":host,"p":int(port),"u":str(u),"t":"hysteria2","sn":sn or "www.apple.com"}
    except: return None

def handle_naive(d):
    try:
        m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d.get('proxy', ''))
        if m: return {"u":m.group(1),"pass":m.group(2),"s":m.group(3),"p":int(m.group(4)),"t":"naive","sn":m.group(3)}
    except: return None

def handle_juicity(d):
    try:
        s, u, pw = d.get('server',''), d.get('uuid'), d.get('password')
        if not (s and u and pw): return None
        host, port = s.rsplit(':', 1)
        return {"s":host,"p":int(port),"u":str(u),"pw":str(pw),"t":"juicity","sn":d.get('sni',host),"cc":d.get('congestion_control','bbr')}
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
        urls = list(set(re.findall(r'https?://[^\s\'"\[\],]+', f.read())))
    
    nodes = []
    for url in urls:
        tag = 'vless' if '/vless' in url else 'hy2' if '/hy' in url else 'naive' if '/naive' in url else 'juicity' if '/juicity' in url else None
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                data = json.loads(resp.read().decode('utf-8', errors='ignore'))
                for d in find_dicts(data):
                    n = None
                    if tag == 'vless': n = handle_vless_reality(d)
                    elif tag == 'hy2': n = handle_hy2_native(d)
                    elif tag == 'naive': n = handle_naive(d)
                    elif tag == 'juicity': n = handle_juicity(d)
                    if not n: n = handle_vless_reality(d) or handle_hy2_native(d) or handle_juicity(d) or handle_naive(d)
                    if n: nodes.append(n)
        except: continue

    uniq, seen, clash_px = [], set(), []
    for n in nodes:
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    for i, n in enumerate(uniq):
        name = f"{get_geo(n['s'])} {n['t'].upper()}_{i+1}"
        px = {"name":name,"server":n['s'],"port":n['p'],"skip-cert-verify":True}
        if n['t'] == 'vless':
            px.update({"type":"vless","uuid":n['u'],"tls":True,"servername":n['sn'],"network":"tcp","udp":True})
            if n.get('pbk'): px.update({"reality-opts":{"public-key":n['pbk'],"short-id":n.get('sid','')}})
        elif n['t'] == 'hysteria2':
            px.update({"type":"hysteria2","password":n['u'],"sni":n['sn']})
