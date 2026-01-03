import json, urllib.request, yaml, os, ssl, warnings, re

warnings.filterwarnings("ignore")

# --- 配置 ---
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

MANUAL_FILE = './urls/manual_json.txt'
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_node_info(item):
    try:
        if not isinstance(item, dict): return None
        srv = item.get('server') or item.get('add') or item.get('address')
        if not srv or str(srv).startswith('127.'): return None
        port = item.get('port') or item.get('server_port') or item.get('port_num')
        if not port and ':' in str(srv): srv, port = str(srv).rsplit(':', 1)
        pwd = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
        if not srv or not port or not pwd: return None

        srv = str(srv).replace('[','').replace(']','')
        port = int(str(port).split(',')[0].strip())
        t = str(item.get('type', '')).lower()
        if 'hy2' in t or 'hysteria2' in t or 'auth' in item: ntype = 'hysteria2'
        elif 'vless' in t or 'uuid' in item: ntype = 'vless'
        else: ntype = 'vless'

        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = item.get('sni') or item.get('servername') or tls_obj.get('server_name') or ""
        
        node = {"server": srv, "port": port, "type": ntype, "secret": str(pwd), "sni": sni}
        ry = item.get('reality-opts') or item.get('reality') or tls_obj.get('reality') or {}
        if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
            node["pbk"] = ry.get('public-key') or ry.get('publicKey')
            node["sid"] = ry.get('short-id') or ry.get('shortId') or ""
        return node
    except: return None

def extract_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(extract_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(extract_dicts(i))
    return res

def main():
    all_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    target_urls = FIXED_SOURCES.copy()
    if os.path.exists(MANUAL_FILE):
        with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
            target_urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))
    
    for url in list(set(target_urls)):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if raw.startswith(('{','[')) else yaml.safe_load(raw)
                for d in extract_dicts(data):
                    node = get_node_info(d)
                    if node: all_nodes.append(node)
        except: continue

    unique_list = []
    seen = set()
    for n in all_nodes:
        key = (n['server'], n['port'], n['secret'])
        if key not in seen: unique_list.append(n); seen.add(key)

    proxies = []
    for i, n in enumerate(unique_list):
        # 更加直观的命名方式：协议 + IP后两位
        suffix = n['server'].split('.')[-1] if '.' in n['server'] else 'v6'
        name = f"{n['type'].upper()}_{suffix}_{i+1}"
        p = {"name": name, "type": n['type'], "server": n['server'], "port": n['port'], "skip-cert-verify": True}
        if n['type'] == 'hysteria2':
            p["password"] = n['secret']
            p["sni"] = n['sni']
        else:
            p["uuid"] = n['secret']
            p["tls"] = True
            p["servername"] = n['sni']
            if n.get('pbk'):
                p["reality-opts"] = {"public-key": n['pbk'], "short-id": n['sid']}
                p["network"] = "tcp"
        proxies.append(p)

    # 增强的分组逻辑
    p_names = [x['name'] for x in proxies]
    conf = {
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 自动测速", "type": "url-test", "proxies": p_names, "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 手动切换", "type": "select", "proxies": ["🚀 自动测速"] + p_names},
            {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT", "🔰 手动切换"]}
        ],
        "rules": [
            "DOMAIN-SUFFIX,google.com,🔰 手动切换",
            "DOMAIN-KEYWORD,youtube,🔰 手动切换",
            "DOMAIN-KEYWORD,github,🔰 手动切换",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🔰 手动切换"
        ]
    }
    
    with open(f"{OUTPUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    print(f"🏁 抓取完成，有效节点数: {len(proxies)}")

if __name__ == "__main__":
    main()
