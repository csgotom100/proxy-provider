import json, urllib.request, yaml, os, ssl, warnings, re, time
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")

OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    try:
        clean_ip = ip.replace('[','').replace(']','')
        if not re.match(r'^\d', clean_ip) and not ':' in clean_ip: return "🏳️"
        url = f"http://ip-api.com/json/{clean_ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            code = json.loads(r.read().decode()).get('countryCode', 'UN')
            return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🏳️"

# --- 🧪 协议实验室：针对样板定制的解析器 ---

def handle_vless_reality(d):
    """适配 VLESS Sing-box (Reality)"""
    try:
        s = d.get('server') or d.get('add')
        p = d.get('server_port') or d.get('port')
        u = d.get('uuid') or d.get('id')
        if not (s and u): return None
        tls = d.get('tls', {})
        real = tls.get('reality', {}) if isinstance(tls, dict) else {}
        return {
            "s": str(s), "p": int(p), "u": str(u), "t": "vless",
            "sn": tls.get('server_name') if isinstance(tls, dict) else d.get('sni', ''),
            "pbk": real.get('public_key'), "sid": real.get('short_id')
        }
    except: return None

def handle_hy2_native(d):
    """适配 HY2 Native (支持端口跳跃)"""
    try:
        s_raw = str(d.get('server', ''))
        u = d.get('auth') or d.get('auth_str') or d.get('password')
        if not s_raw or not u: return None
        host = s_raw.split(':')[0].replace('[','').replace(']','')
        port = re.findall(r'\d+', s_raw.split(':')[1])[0] if ':' in s_raw else 443
        tls = d.get('tls', {})
        sn = d.get('sni') or d.get('server_name')
        if isinstance(tls, dict): sn = tls.get('sni') or tls.get('server_name') or sn
        return {"s": host, "p": int(port), "u": str(u), "t": "hysteria2", "sn": sn or "bing.com"}
    except: return None

def handle_naive(d):
    """适配 NaiveProxy"""
    proxy_str = d.get('proxy', '')
    if not proxy_str.startswith('https://'): return None
    try:
        m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', proxy_str)
        if m: return {"u": m.group(1), "pass": m.group(2), "s": m.group(3), "p": int(m.group(4)), "t": "naive", "sn": m.group(3)}
    except: return None

def handle_juicity(d):
    """适配样板：Juicity (特征：uuid + password + sni)"""
    try:
        s_raw = d.get('server', '')
        u = d.get('uuid')
        pw = d.get('password')
        if not (s_raw and u and pw): return None
        host, port = s_raw.rsplit(':', 1)
        return {
            "s": host, "p": int(port), "u": str(u), "pw": str(pw),
            "t": "juicity", "sn": d.get('sni', host), "cc": d.get('congestion_control', 'bbr')
        }
    except: return None

# --- ⚙️ 核心处理引擎 ---

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
    
    final_nodes = []
    for url in urls:
        # 路由标记
        tag = 'vless' if '/vless' in url else 'hy2' if '/hy' in url else \
              'naive' if '/naive' in url else 'juicity' if '/juicity' in url else None
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                data = json.loads(resp.read().decode('utf-8', errors='ignore'))
                for d in find_dicts(data):
                    node = None
                    if tag == 'vless': node = handle_vless_reality(d)
                    elif tag == 'hy2': node = handle_hy2_native(d)
                    elif tag == 'naive': node = handle_naive(d)
                    elif tag == 'juicity': node = handle_juicity(d)
                    if not node: # 交叉保底
                        node = handle_vless_reality(d) or handle_hy2_native(d) or handle_juicity(d) or handle_naive(d)
                    if node: final_nodes.append(node)
        except: continue

    uniq, seen = [], set()
    for n in final_nodes:
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    clash_px = []
    for i, n in enumerate(uniq):
        flag = get_geo(n['s'])
        name = f"{flag} {n['t'].upper()}_{i+1}"
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'hysteria2':
            px.update({"password": n['u'], "sni": n['sn']})
        elif n['t'] == 'vless':
            px.update({"uuid": n['u'], "tls": True, "servername": n['sn'], "network": "tcp"})
            if n.get('pbk'): px.update({"reality-opts": {"public-key": n['pbk'], "short-id": n.get('sid', '')}})
        elif n['t'] == 'naive':
            px.update({"username": n['u'], "password": n['pass'], "proxy-octet-stream": True})
        elif n['t'] == 'juicity':
            px.update({"uuid": n['u'], "password": n['pw'], "sni": n['sn'], "congestion-control": n['cc']})
        
        clash_px.append(px)

    conf = {
        "proxies": clash_px,
        "proxy-groups": [{"name": "🚀 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300}],
        "rules": ["MATCH,🚀 自动选择"]
    }

    with open(f"{OUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    
    print(f"✅ 大功告成！全协议精准汇总节点总数: {len(clash_px)}")

if __name__ == "__main__":
    main()
