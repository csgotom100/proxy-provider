import json, urllib.request, yaml, os, ssl, warnings, re, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    """解析单个节点字典，适配 sing-box/xray/clash 结构"""
    try:
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        
        # --- Hysteria2 (适配 Alvin9999 的 config.json) ---
        if 'hysteria2' in ptype:
            s = d.get('server') or d.get('add')
            p = d.get('server_port') or d.get('port')
            u = d.get('auth_str') or d.get('password') or d.get('auth')
            if not (s and u): return None
            # 提取 SNI：sing-box 嵌套在 tls 字段，Clash 是扁平的
            tls = d.get('tls', {})
            sni = d.get('sni') or d.get('servername')
            if isinstance(tls, dict): sni = tls.get('server_name') or sni
            
            return {
                "t": "hysteria2", "s": str(s).replace('[','').replace(']',''), 
                "p": int(p), "u": str(u), "sn": sni, "insecure": 1
            }

        # --- VLESS (适配 Reality 嵌套结构) ---
        if 'vless' in ptype:
            s = d.get('server') or d.get('add')
            p = d.get('server_port') or d.get('port')
            u = d.get('uuid') or d.get('id')
            if not (s and u): return None
            
            # 处理多层嵌套的 Reality 参数
            tls = d.get('tls', {})
            ry = {}
            if isinstance(tls, dict):
                ry = tls.get('reality', {})
                sni = tls.get('server_name') or d.get('sni')
                fp = tls.get('utls', {}).get('fingerprint') or d.get('fp')
            else:
                sni = d.get('sni')
                fp = d.get('fp')

            ro = d.get('reality-opts', {}) # Clash 风格
            pbk = ry.get('public_key') or ro.get('public-key')
            sid = ry.get('short_id') or ro.get('short-id')

            params = {
                "security": "reality" if pbk else "tls",
                "sni": sni, "pbk": pbk, "sid": sid, "fp": fp,
                "type": d.get('transport', {}).get('type') or d.get('network', 'tcp'),
                "flow": d.get('flow')
            }
            return {"t": "vless", "s": str(s), "p": int(p), "u": str(u), "params": {k: v for k, v in params.items() if v}}

        # --- NaiveProxy ---
        if 'proxy' in d and str(d['proxy']).startswith('https://'):
            return {"t": "naive", "raw": d['proxy'], "s": "naive_node", "p": 443}
            
    except: return None

def find_nodes(obj):
    """递归挖掘所有可能的节点定义"""
    if isinstance(obj, dict):
        if 'type' in obj and obj['type'] in ['vless', 'hysteria2', 'naive']:
            yield obj
        # 扫描 sing-box 的 outbounds 和 Clash 的 proxies
        for key in ['outbounds', 'proxies']:
            if key in obj and isinstance(obj[key], list):
                for item in obj[key]: yield from find_nodes(item)
        # 深度扫描其他分支
        for v in obj.values():
            if isinstance(v, (dict, list)): yield from find_nodes(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_nodes(i)

def fetch_url(url):
    """单个 URL 下载与解析任务"""
    nodes = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read().decode('utf-8', errors='ignore')
            try: data = json.loads(raw)
            except: data = yaml.safe_load(raw)
            for d in find_nodes(data):
                n = parse_node(d)
                if n: nodes.append(n)
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return nodes

def main():
    if not os.path.exists(MANUAL_FILE): return
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    all_nodes = []
    # 使用线程池加速，max_workers=10 表示同时下载 10 个文件
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            all_nodes.extend(future.result())

    # 去重
    unique_nodes, seen = [], set()
    for n in all_nodes:
        key = (n['s'], n['p'], n.get('u', n.get('raw', '')))
        if key not in seen: unique_nodes.append(n); seen.add(key)

    clash_proxies, v2_links = [], []
    for i, n in enumerate(unique_nodes):
        host_tag = n['s'].split('.')[-1] if '.' in n['s'] else 'node'
        nm = f"{i+1:02d}_{n['t'].upper()}_{host_tag}"
        
        if n['t'] == 'hysteria2':
            clash_proxies.append({"name": nm, "type": "hysteria2", "server": n['s'], "port": n['p'], "password": n['u'], "sni": n.get('sn'), "skip-cert-verify": True})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n.get('sn','')}&insecure=1#{nm}")
        elif n['t'] == 'vless':
            p = n['params']
            px = {"name": nm, "type": "vless", "server": n['s'], "port": n['p'], "uuid": n['u'], "tls": True, "skip-cert-verify": True}
            if p.get("security") == "reality": 
                px["reality-opts"] = {"public-key": p.get("pbk"), "short-id": p.get("sid", "")}
            if p.get("sni"): px["servername"] = p["sni"]
            clash_proxies.append(px)
            query = "&".join([f"{k}={v}" for k, v in p.items()])
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?{query}#{nm}")
        elif n['t'] == 'naive':
            v2_links.append(f"{n['raw']}#{nm}")

    # 写入输出
    if clash_proxies:
        with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
            yaml.dump({"proxies": clash_proxies, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [px['name'] for px in clash_proxies] + ["DIRECT"]}, {"name": "⚡ 自动选择", "type": "url-test", "proxies": [px['name'] for px in clash_proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300}], "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)
    
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())
    print(f"成功提取 {len(unique_nodes)} 个节点")

if __name__ == "__main__":
    main()
