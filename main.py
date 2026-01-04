import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    """从字典中精确提取节点信息"""
    try:
        ptype = str(d.get('type', '')).lower()
        
        # --- Hysteria2 提取 ---
        if 'hysteria2' in ptype:
            host = d.get('server') or d.get('add')
            pw = d.get('password') or d.get('auth')
            if host and pw:
                return {
                    "t": "hysteria2",
                    "s": str(host).strip("[]"),
                    "p": int(d.get('port', 443)),
                    "u": str(pw),
                    "sn": d.get('sni') or d.get('servername', ''),
                    "insecure": 1
                }

        # --- VLESS 提取 ---
        if 'vless' in ptype:
            host = d.get('server') or d.get('add')
            uuid = d.get('uuid') or d.get('id')
            if host and uuid:
                ro = d.get('reality-opts', {})
                params = {
                    "security": "reality" if ro else "tls",
                    "sni": d.get('servername') or d.get('sni'),
                    "pbk": ro.get('public-key'),
                    "sid": ro.get('short-id'),
                    "fp": d.get('client-fingerprint') or d.get('fp'),
                    "type": d.get('network', 'tcp'),
                    "flow": d.get('flow')
                }
                return {"t": "vless", "s": str(host), "p": int(d.get('port', 443)), "u": str(uuid), "params": {k: v for k, v in params.items() if v}}

        # --- Naive 提取 ---
        if 'proxy' in d and str(d['proxy']).startswith('https://'):
            return {"t": "naive", "raw": d['proxy'], "s": "naive_node", "p": 443}
    except:
        return None

def regex_fallback(content):
    """正则保底：如果 YAML 解析漏掉 Hy2，直接从文本里抠出关键参数"""
    nodes = []
    # 匹配 Hysteria2 文本块
    hy2_blocks = re.findall(r'-\s*{[^}]*type:\s*hysteria2[^}]*}', content, re.S)
    for block in hy2_blocks:
        try:
            srv = re.search(r'server:\s*([^\s,}]*)', block).group(1)
            port = re.search(r'port:\s*(\d+)', block).group(1)
            pw = re.search(r'password:\s*([^\s,}]*)', block).group(1)
            sni = re.search(r'sni:\s*([^\s,}]*)', block)
            nodes.append({
                "t": "hysteria2", "s": srv.strip('"\''), "p": int(port), 
                "u": pw.strip('"\''), "sn": sni.group(1).strip('"\'') if sni else "", "insecure": 1
            })
        except: continue
    return nodes

def main():
    if not os.path.exists(MANUAL_FILE): return
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    
    nodes = []
    # 1. 尝试标准 YAML 解析
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            plist = data.get('proxies', [])
            for p in plist:
                n = parse_node(p)
                if n: nodes.append(n)
    except: pass

    # 2. 如果没抓到 Hy2，启动正则保底
    if not any(n['t'] == 'hysteria2' for n in nodes):
        nodes.extend(regex_fallback(content))

    # 3. 处理 URL 订阅
    urls = re.findall(r'https?://[^\s\'"\[\],]+', content)
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                d = yaml.safe_load(raw)
                if isinstance(d, dict) and 'proxies' in d:
                    for p in d['proxies']:
                        n = parse_node(p)
                        if n: nodes.append(n)
        except: continue

    # 去重与输出
    unique_nodes, seen = [], set()
    for n in nodes:
        key = (n['s'], n['p'], n.get('u', ''))
        if key not in seen: unique_nodes.append(n); seen.add(key)

    clash_proxies, v2_links = [], []
    for i, n in enumerate(unique_nodes):
        nm = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        if n['t'] == 'hysteria2':
            clash_proxies.append({"name": nm, "type": "hysteria2", "server": n['s'], "port": n['p'], "password": n['u'], "sni": n['sn'], "skip-cert-verify": True})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure=1#{nm}")
        elif n['t'] == 'vless':
            p = n['params']
            px = {"name": nm, "type": "vless", "server": n['s'], "port": n['p'], "uuid": n['u'], "tls": True, "skip-cert-verify": True}
            if p.get("security") == "reality": px["reality-opts"] = {"public-key": p["pbk"], "short-id": p.get("sid", "")}
            if p.get("sni"): px["servername"] = p["sni"]
            clash_proxies.append(px)
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?security={p.get('security','tls')}&sni={p.get('sni','')}&pbk={p.get('pbk','')}&sid={p.get('sid','')}#{nm}")
        elif n['t'] == 'naive':
            v2_links.append(f"{n['raw']}#{nm}")

    # 保存文件
    if clash_proxies:
        conf = {"proxies": clash_proxies, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [px['name'] for px in clash_proxies] + ["DIRECT"]}], "rules": ["MATCH,🚀 节点选择"]}
        with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
            yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())

if __name__ == "__main__":
    main()
