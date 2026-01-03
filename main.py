import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")

# 路径强制锁定：确保在 GitHub Actions 环境中指向仓库根目录
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')

# 确保输出目录存在
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    """
    单节点综合解析器
    支持：NaiveProxy (Alvin格式), Hysteria2 (sing-box/xray), VLESS Reality (sing-box/xray)
    """
    try:
        # --- 1. NaiveProxy 逻辑 ---
        if 'proxy' in d and 'https://' in str(d['proxy']):
            m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d['proxy'])
            if m:
                return {
                    "t": "naive", "u": m.group(1), "pw": m.group(2),
                    "s": m.group(3), "p": int(m.group(4)), "sn": m.group(3)
                }

        # --- 2. 基础字段提取 ---
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        s = d.get('server') or d.get('add')
        p = d.get('server_port') or d.get('port')
        u = d.get('uuid') or d.get('id') or d.get('auth') or d.get('password') or d.get('auth_str')
        
        if not s or not u or not p: return None

        # --- 3. Hysteria2 逻辑 ---
        if 'hysteria2' in ptype:
            host = str(s).split(':')[0].replace('[','').replace(']','')
            return {
                "t": "hysteria2", "s": host, "p": int(p), "u": str(u),
                "sn": d.get('tls',{}).get('server_name') or d.get('sni')
            }

        # --- 4. VLESS 逻辑 (严格匹配你提供的 Reality 结构) ---
        if 'vless' in ptype:
            sec, sn, pbk, sid, fp = 'none', None, None, None, None
            
            # A. 优先尝试 sing-box 嵌套结构 (tls -> reality)
            tls = d.get('tls', {})
            if tls and tls.get('enabled'):
                sec = 'tls'
                sn = tls.get('server_name')
                fp = tls.get('utls', {}).get('fingerprint')
                ry = tls.get('reality', {})
                if ry and ry.get('enabled'):
                    sec = 'reality'
                    pbk = ry.get('public_key')
                    sid = ry.get('short_id')
            
            # B. 兼容 Xray streamSettings 结构
            ss = d.get('streamSettings', {})
            net = d.get('transport', {}).get('type') or ss.get('network') or d.get('net', 'tcp')
            if ss:
                sec = ss.get('security') or sec
                rl = ss.get('realitySettings')
                if rl:
                    sn = rl.get('serverName') or sn
                    pbk = rl.get('publicKey') or pbk
                    sid = rl.get('shortId') or sid
                    fp = rl.get('fingerprint') or fp

            return {
                "t": "vless", "s": str(s), "p": int(p), "u": str(u),
                "net": net, "sec": sec, "sn": sn, "pbk": pbk, "sid": sid, "fp": fp
            }
    except:
        return None
    return None

def find_dicts(obj):
    """递归遍历 JSON 树，寻找所有字典对象"""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values(): yield from find_dicts(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_dicts(i)

def main():
    if not os.path.exists(MANUAL_FILE):
        print(f"❌ 错误: 找不到文件 {MANUAL_FILE}")
        return

    # 提取订阅源 URL
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    print(f"📡 找到 {len(urls)} 个源地址，准备抓取...")
    all_nodes = []

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if '{' in raw else yaml.safe_load(raw)
                source_count = 0
                for d in find_dicts(data):
                    node = parse_node(d)
                    if node:
                        all_nodes.append(node)
                        source_count += 1
                print(f"✅ 源 {url[:30]}... 提取到 {source_count} 个节点")
        except Exception as e:
            print(f"⚠️ 抓取失败 {url}: {e}")

    # 去重
    unique_nodes, seen = [], set()
    for n in all_nodes:
        key = (n['s'], n['p'], n.get('u') or n.get('pw'))
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    clash_proxies, v2_links = [], []
    for i, n in enumerate(unique_nodes):
        node_name = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        px = {"name": node_name, "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'vless':
            px.update({"type": "vless", "uuid": n['u'], "udp": True, "network": n.get('net', 'tcp')})
            if n['sec'] in ['tls', 'reality']:
                px["tls"] = True
                if n['sn']: px["servername"] = n['sn']
                if n['fp']: px["client-fingerprint"] = n['fp']
            if n['sec'] == 'reality' and n['pbk']:
                px["reality-opts"] = {"public-key": n['pbk'], "short-id": n['sid'] or ""}
            
            # 生成严格格式的 vless 链接
            link = f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security={n['sec']}&type={n.get('net','tcp')}"
            if n['sn']: link += f"&sni={n['sn']}"
            if n['fp']: link += f"&fp={n['fp']}"
            if n['pbk']: link += f"&pbk={n['pbk']}&sid={n['sid'] or ''}"
            v2_links.append(f"{link}#{node_name}")
        
        elif n['t'] == 'hysteria2':
            px.update({"type": "hysteria2", "password": n['u'], "sni": n['sn']})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn'] or ''}#{node_name}")
        
        elif n['t'] == 'naive':
            px.update({"type": "http", "username": n['u'], "password": n['pw'], "tls": True, "sni": n['sn'], "proxy-octet-stream": True})
            v2_links.append(f"http://{n['u']}:{n['pw']}@{n['s']}:{n['p']}#{node_name}")

        clash_proxies.append(px)

    if not clash_proxies:
        print("🛑 未提取到任何节点，跳过写入。")
        return

    # 写入 Clash 配置文件
    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [p['name'] for p in clash_proxies] + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300}
        ],
        "rules": ["MATCH,🚀 节点选择"]
    }

    # 强制执行文件写入
    try:
        with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f:
            f.write("\n".join(v2_links))
        with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f:
            f.write(base64.b64encode("\n".join(v2_links).encode()).decode())
        
        print(f"🎉 任务完成！节点总数: {len(clash_proxies)}")
        print(f"📂 文件已保存至: {OUT_DIR}")
    except Exception as e:
        print(f"❌ 写入文件失败: {e}")

if __name__ == "__main__":
    main()
