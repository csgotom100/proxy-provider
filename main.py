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
            s = d.get('server') or d.get('add')
            p = d.get('server_port') or d.get('port')
            u = d.get('uuid') or d.get('id')
        if not (s and u): return None
        ss = d.get('streamSettings', {})
        real = ss.get('realitySettings', d.get('reality', {}))
        sn = real.get('serverName') or ss.get('tlsSettings', {}).get('serverName') or d.get('sni', 'www.apple.com')
        return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","sn":sn,"pbk":real.get('publicKey') or d.get('public_key'),"sid":real.get('shortId') or d.get('short_id'),"net":ss.get('network','tcp')}
    except: return None

def handle_hy2(d):
    try:
        s_raw = str(d.get('server', ''))
        u = d.get('auth') or d.get('auth_str') or d.get('password')
        if not s_raw or not u or d.get('protocol') == 'freedom': return None
        host = s_raw.split(':')[0].replace('[','').replace(']','')
        port = re.findall(r'\d+', s_raw.split(':')[1])[0] if ':' in s_raw else 443
        return {"s":host,"p":int(port),"u":str(u),"t":"hysteria2","sn":d.get('sni') or d.get('server_name') or "www.apple.com"}
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

def handle_sq(d):
    try:
        addr = d.get('addr') or d.get('settings',{}).get('vnext',[{}])[0].get('address')
        u, pw = d.get('username') or d.get('auth'), d.get('password')
        if (d.get('type') != 'shadowquic' and d.get('protocol') != 'shadowquic') or not (addr and pw): return None
        host, port = addr.rsplit(':', 1)
        return {"s":host,"p":int(port),"u":u or
