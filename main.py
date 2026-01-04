import json, urllib.request, yaml, os, ssl, warnings, re, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def clean_json(raw_str):
    """移除 JSON 中的 // 和 /* */ 注释，防止解析失败"""
    content = re.sub(r'//.*', '', raw_str)
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.S)
    return content

def parse_node(d):
    """解析节点字典，强制适配 Alvin9999 的多种非标格式"""
    try:
        # 兼容 protocol 或 type 字段
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        
        # --- Hysteria2 专项 (针对 Alvin9999 sing-box 格式) ---
        if 'hysteria2' in ptype or 'hy2' in ptype:
            s = d.get('server') or d.get('add')
            p = d.get('server_port') or d.get('port')
            # 关键：Alvin9999 的 sing-box 用 auth_str，Clash 用 password
            u = d.get('auth_str') or d.get('password') or d.get('auth')
            
            if s and u and p:
                tls = d.get('tls', {})
                sni = d.get('sni') or d.get('servername')
                if isinstance(tls, dict):
                    sni = tls.get('server_name') or sni
                
                return {
                    "t": "hysteria2", 
                    "s": str(s).replace('[','').replace(']',''), 
                    "p": int(p), "u": str(u), 
                    "sn": sni or "", "insecure": 1
                }

        # --- VLESS 专项 ---
        if 'vless' in ptype:
            s = d.get('server') or d.get('add')
            p = d.get('server_port') or d.get('port')
            u = d.get('uuid') or d.get('id')
            if not (s and u): return None
            
            tls = d.get('tls', {})
            pbk, sid, sni, fp = None, None, None, None
            if isinstance(tls, dict):
                ry = tls.get('reality', {})
                pbk = ry.get('public_key')
                sid = ry.get('short_id')
                sni = tls.get('server_name')
                fp = tls.get('utls', {}).get('fingerprint')
            
            # Clash 扁平化兜底
            ro = d.get('reality-opts', {})
            pbk = pbk or ro.get('public-key')
            sid = sid or ro.get('short-id')
            sni = sni or d.get('servername') or d.get('sni')

            params = {
                "security": "reality" if pbk else "tls",
                "sni": sni, "pbk": pbk, "sid": sid, "fp": fp or "chrome",
                "type": d.get('transport', {}).get('type') or d.get('network', 'tcp'),
                "flow": d.get('flow')
            }
            return {"t": "vless", "s": str(s), "p": int(p), "u": str(u), "params": {k: v for k, v in params.items() if v}}
            
    except: return None

def find_nodes_recursive(obj):
    """深度优先遍历，寻找所有包含 server/port 且类似节点的字典"""
    nodes = []
    if isinstance(obj, dict):
        if 'type' in obj or 'protocol' in obj:
            n = parse_node(obj)
            if n: nodes.append(n)
        for v in obj.values():
            nodes.extend(find_nodes_recursive(v))
    elif isinstance(obj, list):
        for item in obj:
            nodes.extend(find_nodes_recursive(item))
    return nodes

def fetch_url(url):
    """下载、清洗并解析"""
    nodes = []
    try:
        req = urllib.request.Request(url.strip(), headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
            raw = resp.read().decode('utf-8', errors='ignore')
            # 关键步骤：清洗掉 JSON 中的注释
            cleaned = clean_json(raw)
            try:
                data = json.loads(cleaned)
            except:
                data = yaml.safe_load(cleaned)
            
            nodes = find_nodes_recursive(data)
    except Exception as e:
        print(f"跳过失效 URL: {url[:40]}... 错误: {e}")
    return nodes

def main():
    if not os.path.exists(MANUAL_FILE): return
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    all_nodes = []
    print(f"正在多线程处理 {len(urls)} 个链接...")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_url, url): url for url in urls}
        for future in as_completed(futures):
            all_nodes.extend(future.result())

    # 去重
    unique_nodes, seen = [], set()
    for n in all_nodes:
        key = (n['s'], n['p'], n.get('u', ''))
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    clash_proxies, v2_links = [], []
    for i, n in enumerate(unique_nodes):
        nm = f"{i+1:02d}_{n['t'].upper()}_{n['s'].split('.')[-1]}"
        
        if n['t'] == 'hysteria2':
            clash_proxies.append({
                "name": nm, "type": "hysteria2", "server": n['s'], "port": n['p'], 
                "password": n['u'], "sni": n['sn'], "skip-cert-verify": True
            })
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure=1#{nm}")
        elif n['t'] == 'vless':
            p = n['params']
            px = {"name": nm, "type": "vless", "server": n['s'], "port": n['p'], "uuid": n['u'], "tls": True, "skip-cert-verify": True}
            if p.get("security") == "reality":
                px["reality-opts"] = {"public-key": p.get("pbk"), "short-id": p.get("sid", "")}
            if p.get("sni"): px["servername"] = p["sni"]
            clash_proxies.append(px)
            query = "&".join([f"{k}={v}" for k, v in p.items()])
            v2_links.append(f"vless://{n['u']}@{n['s']}:{n['p']}?{query}#{nm}")

    # 结果导出
    if clash_proxies:
        conf = {
            "proxies": clash_proxies,
            "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [px['name'] for px in clash_proxies] + ["DIRECT"]}, {"name": "⚡ 自动选择", "type": "url-test", "proxies": [px['name'] for px in clash_proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300}],
            "rules": ["MATCH,🚀 节点选择"]
        }
        with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
            yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
            
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())
    print(f"✅ 处理完成！总计捕获: {len(unique_nodes)} 个有效节点")

if __name__ == "__main__":
    main()
