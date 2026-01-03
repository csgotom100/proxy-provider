import json, urllib.request, yaml, os, ssl, warnings, re, base64, time
from datetime import datetime, timedelta, timezone

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
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ip/singbox/2/config.json"
]

OUT_DIR = './sub'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    """获取国旗 Emoji，增加容错"""
    try:
        clean_ip = ip.replace('[','').replace(']','')
        # 使用 fields=countryCode 减少数据量
        url = f"http://ip-api.com/json/{clean_ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read().decode())
            code = data.get('countryCode', 'UN')
            return "".join(chr(ord(c) + 127397) for c in code.upper())
    except:
        return "🏳️"

def get_node(item):
    """解析节点信息，修复所有潜在语法断点"""
    try:
        if not isinstance(item, dict): return None
        s = item.get('server') or item.get('add') or item.get('address')
        p = item.get('port') or item.get('server_port') or item.get('port_num')
        u = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
        if not (s and p and u): return None
        
        s, p = str(s).replace('[','').replace(']',''), int(str(p).split(',')[0].strip())
        t = str(item.get('type', '')).lower()
        nt = 'hysteria2' if ('hy2' in t or 'hysteria2' in t or 'auth' in item) else 'vless'
        tls = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sn = item.get('sni') or item.get('servername') or tls.get('server_name') or ""
        
        node = {"s": s, "p": p, "t": nt, "u": str(u), "sn": sn}
        ry = item.get('reality-opts') or item.get('reality') or tls.get('reality') or {}
        if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
            node["pbk"] = ry.get('public-key') or ry.get('publicKey')
            node["sid"] = ry.get('short-id') or ry.get('shortId') or ""
        return node
    except:
        return None

def ext_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(ext_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(ext_dicts(i))
    return res

def main():
    raw_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    for url in list(set(FIXED_SOURCES)):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if raw.startswith(('{','[')) else yaml.safe_load(raw)
                for d in ext_dicts(data):
                    node = get_node(d)
                    if node: raw_nodes.append(node)
        except: continue

    uniq, seen = [], set()
    for n in raw_nodes:
        key = (n['s'], n['p'], n['u'])
        if key not in seen:
            uniq.append(n)
            seen.add(key)

    clash_px, raw_links = [], []
    # 强制北京时间
    bj_now = datetime.now(timezone(timedelta(hours=8)))
    bj_time = bj_now.strftime("%Y-%m-%d %H:%M")
    
    for i, n in enumerate(uniq):
        flag = get_geo(n['s'])
        name = f"{flag} {n['t'].upper()}_{n['s'].split('.')[-1]}_{i+1}"
        
        # 节点配置
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        if n['t'] == 'hysteria2':
            px["password"], px["sni"] = n['u'], n['sn']
        else:
            px.update({"uuid": n['u'], "tls": True, "servername": n['sn']})
            if "pbk" in n:
                px.update({"reality-opts": {"public-key": n['pbk'], "short-id": n['sid']}, "network": "tcp"})
        clash_px.append(px)
        
        # 链接转换
        from urllib.parse import quote
        en = quote(name)
        if n['t'] == 'hysteria2':
            raw_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure=1#{en}")
        else:
            l = f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security=tls&sni={n['sn']}"
            if "pbk" in n:
                l = l.replace("security=tls", "security=reality") + f"&fp=chrome&pbk={n['pbk']}&sid={n['sid']}"
            raw_links.append(f"{l}#{en}")
        
        # API 频率限制保护
        if i % 10 == 0: time.sleep(0.5)

    # 生成配置
    px_names = [p['name'] for p in clash_px]
    conf = {
        "proxies": clash_px,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": px_names, "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 手动切换", "type": "select", "proxies": ["🚀 自动选择"] + px_names},
            {"name": f"🕒 更新: {bj_time}", "type": "select", "proxies": ["🚀 自动选择"]}
        ],
        "rules": ["MATCH,🔰 手动切换"]
    }

    with open(f"{OUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    
    links = "\n".join(raw_links)
    with open(f"{OUT_DIR}/node_links.txt", 'w', encoding='utf-8') as f:
        f.write(links)
    with open(f"{OUT_DIR}/subscribe_base64.txt", 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(links.encode()).decode())

    print(f"成功! 节点: {len(uniq)} | 北京时间: {bj_time}")

if __name__ == "__main__":
    main()
