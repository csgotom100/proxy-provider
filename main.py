import json, urllib.request, yaml, os, ssl, warnings, re, base64, time
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")

# --- 1. 配置源 ---
FIXED_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml"
]
OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    try:
        clean_ip = ip.replace('[','').replace(']','')
        url = f"http://ip-api.com/json/{clean_ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read().decode())
            code = data.get('countryCode', 'UN')
            return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🏳️"

def get_node(item):
    """全协议解析逻辑"""
    try:
        if not isinstance(item, dict): return None
        # 1. 基础协议识别
        t = str(item.get('type', '')).lower()
        
        # --- Juicity 解析 ---
        if 'juicity' in t or 'juicity' in str(item.keys()):
            s = item.get('server') or item.get('address')
            p = item.get('port') or item.get('server_port')
            u = item.get('uuid') or item.get('user_id')
            if s and p and u:
                return {"s": str(s), "p": int(p), "t": "juicity", "u": str(u), "sn": item.get('sni', '')}

        # --- NaiveProxy 解析 ---
        if 'proxy' in item and 'address' in item:
            proxy_uri = item.get('proxy', '') # https://user:pass@host:port
            if 'https://' in proxy_uri:
                auth, addr = proxy_uri.replace('https://', '').split('@')
                user, pwd = auth.split(':')
                s, p = addr.split(':')
                return {"s": s, "p": int(p), "t": "naive", "u": user, "pass": pwd, "sn": s}

        # --- Hysteria2/VLESS 通用解析 ---
        s = item.get('server') or item.get('add') or item.get('address')
        p = item.get('port') or item.get('server_port')
        u = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
        if not (s and p and u): return None
        
        s, p = str(s).replace('[','').replace(']',''), int(str(p).split(',')[0].strip())
        nt = 'hysteria2' if ('hy2' in t or 'hysteria2' in t or 'auth' in item) else 'vless'
        tls = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sn = item.get('sni') or item.get('servername') or tls.get('server_name') or ""
        
        node = {"s": s, "p": p, "t": nt, "u": str(u), "sn": sn}
        ry = item.get('reality-opts') or item.get('reality') or tls.get('reality') or {}
        if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
            node["pbk"], node["sid"] = (ry.get('public-key') or ry.get('publicKey')), (ry.get('short-id') or ry.get('shortId') or "")
        return node
    except: return None

def ext_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj); [res.extend(ext_dicts(v)) for v in obj.values()]
    elif isinstance(obj, list):
        [res.extend(ext_dicts(i)) for i in obj]
    return res

def main():
    all_urls = FIXED_SOURCES.copy()
    if os.path.exists(MANUAL_FILE):
        with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
            all_urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))

    raw_nodes = []
    for url in list(set(all_urls)):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if raw.startswith(('{','[')) else yaml.safe_load(raw)
                for d in ext_dicts(data):
                    n = get_node(d)
                    if n: raw_nodes.append(n)
        except: continue

    uniq, seen = [], set()
    for n in raw_nodes:
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    clash_px = []
    bj_time = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")
    
    for i, n in enumerate(uniq):
        flag = get_geo(n['s'])
        name = f"{flag} {n['t'].upper()}_{n['s'].split('.')[-1]}_{i+1}"
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'hysteria2':
            px["password"], px["sni"] = n['u'], n['sn']
        elif n['t'] == 'juicity':
            px.update({"uuid": n['u'], "sni": n['sn'], "conntrack": True})
        elif n['t'] == 'naive':
            px.update({"username": n['u'], "password": n['pass'], "sni": n['sn']})
        elif n['t'] == 'vless':
            px.update({"uuid": n['u'], "tls": True, "servername": n['sn']})
            if "pbk" in n: px.update({"reality-opts": {"public-key": n['pbk'], "short-id": n['sid']}, "network": "tcp"})
        
        clash_px.append(px)
        if i % 5 == 0: time.sleep(0.2)

    conf = {
        "proxies": clash_px,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 手动切换", "type": "select", "proxies": ["🚀 自动选择"] + [p['name'] for p in clash_px]},
            {"name": f"🕒 更新: {bj_time}", "type": "select", "proxies": ["🚀 自动选择"]}
        ],
        "rules": ["MATCH,🔰 手动切换"]
    }

    with open(f"{OUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    
    print(f"成功! 节点总数: {len(clash_px)} | 北京时间: {bj_time}")

if __name__ == "__main__":
    main()
