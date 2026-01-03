import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")

# --- 1. 配置源 ---
FIXED_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ip/singbox/2/config.json"
]

OUT_DIR = './sub'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_node(item):
    try:
        if not isinstance(item, dict): return None
        s = item.get('server') or item.get('add') or item.get('address')
        p = item.get('port') or item.get('server_port') or item.get('port_num')
        u = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
        if not s or not p or not u: return None
        s = str(s).replace('[','').replace(']','')
        p = int(str(p).split(',')[0].strip())
        t = str(item.get('type', '')).lower()
        nt = 'hysteria2' if ('hy2' in t or 'hysteria2' in t or 'auth' in item) else 'vless'
        tls = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sn = item.get('sni') or item.get('servername') or tls.get('server_name') or ""
        res = {"s": s, "p": p, "t": nt, "u": str(u), "sn": sn}
        ry = item.get('reality-opts') or item.get('reality') or tls.get('reality') or {}
        if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
            res["pbk"] = ry.get('public-key') or ry.get('publicKey')
            res["sid"] = ry.get('short-id') or ry.get('shortId') or ""
        return res
    except: return None

def ext_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(ext_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(ext_dicts(i))
    return res

def main():
    nodes = []
    urls = FIXED_SOURCES.copy()
    if os.path.exists('./urls/manual_json.txt'):
        with open('./urls/manual_json.txt', 'r') as f:
            urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))
    
    for url in list(set(urls)):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if raw.startswith(('{','[')) else yaml.safe_load(raw)
                for d in ext_dicts(data):
                    n = get_node(d)
                    if n: nodes.append(n)
        except: continue

    uniq = []
    seen = set()
    for n in nodes:
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    clash_px, raw_links = [], []
    for i, n in enumerate(uniq):
        name = f"{n['t'].upper()}_{n['s'].split('.')[-1]}_{i+1}"
        # Clash
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        if n['t'] == 'hysteria2':
            px["password"], px["sni"] = n['u'], n['sn']
        else:
            px.update({"uuid": n['u'], "tls": True, "servername": n['sn']})
            if "pbk" in n:
                px.update({"reality-opts": {"public-key": n['pbk'], "short-id": n['sid']}, "network": "tcp"})
        clash_px.append(px)
        # URI
        from urllib.parse import quote
        en = quote(name)
        if n['t'] == 'hysteria2':
            raw_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure=1#{en}")
        else:
            l = f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security=tls&sni={n['sn']}"
            if "pbk" in n: l = l.replace("security=tls", "security=reality") + f"&fp=chrome&pbk={n['pbk']}&sid={n['sid']}"
            raw_links.append(f"{l}#{en}")

    # Save
    conf = {"proxies": clash_px, "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [p['name'] for p in clash_px]}], "rules": ["MATCH,PROXY"]}
    with open(f"{OUT_DIR}/clash.yaml", 'w') as f: yaml.dump(conf, f, sort_keys=False)
    
    links = "\n".join(raw_links)
    with open(f"{OUT_DIR}/node_links.txt", 'w') as f: f.write(links)
    with open(f"{OUT_DIR}/subscribe_base64.txt", 'w') as f:
        f.write(base64.b64encode(links.encode()).decode())
    print(f"Done! Nodes: {len(uniq)}")

if __name__ == "__main__":
    main()
