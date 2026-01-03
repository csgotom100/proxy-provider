import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
OUT_DIR, MANUAL_FILE = './sub', './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    """单字典节点解析"""
    try:
        # 1. NaiveProxy 匹配
        if 'proxy' in d and 'https://' in str(d['proxy']):
            m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d['proxy'])
            if m:
                return {"u":m.group(1),"pw":m.group(2),"s":m.group(3),"p":int(m.group(4)),"t":"naive","sn":m.group(3)}

        # 2. 提取基础信息
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        s = d.get('server') or d.get('add')
        p = d.get('server_port') or d.get('port')
        u = d.get('uuid') or d.get('id') or d.get('auth') or d.get('password') or d.get('auth_str')
        
        if not s or not u or not p: return None

        # 3. Hysteria2
        if 'hysteria2' in ptype:
            host = str(s).split(':')[0].replace('[','').replace(']','')
            return {"s":host,"p":int(p),"u":str(u),"t":"hysteria2","sn":d.get('tls',{}).get('server_name') or d.get('sni')}

        # 4. VLESS (严格按照 sing-box 结构)
        if 'vless' in ptype:
            sec, sn, pbk, sid, fp = 'none', None, None, None, None
            # 优先看 tls 节点 (sing-box)
            tls = d.get('tls', {})
            if tls:
                sec = 'tls'
                sn = tls.get('server_name')
                fp = tls.get('utls', {}).get('fingerprint')
                ry = tls.get('reality', {})
                if ry:
                    sec = 'reality'
                    pbk = ry.get('public_key')
                    sid = ry.get('short_id')
            
            # 兼容 streamSettings (xray)
            ss = d.get('streamSettings', {})
            net = d.get('transport', {}).get('type') or ss.get('network') or d.get('net', 'tcp')
            if ss:
                sec = ss.get('security') or sec
                rl = ss.get('realitySettings')
                if rl:
                    sn, pbk, sid, fp = rl.get('serverName'), rl.get('publicKey'), rl.get('shortId'), rl.get('fingerprint')

            return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","net":net,"sec":sec,"sn":sn,"pbk":pbk,"sid":sid,"fp":fp}
    except:
        return None
    return None

def find_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values(): yield from find_dicts(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_dicts(i)

def main():
    if not os.path.exists(MANUAL_FILE):
        print(f"❌ 找不到文件: {MANUAL_FILE}")
        return

    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    print(f"🔍 找到 {len(urls)} 个订阅源地址")
    nodes = []

    for url in urls:
        try:
            print(f"📡 正在下载: {url}")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if '{' in raw else yaml.safe_load(raw)
                count = 0
                for d in find_dicts(data):
                    n = parse_node(d)
                    if n: 
                        nodes.append(n)
                        count += 1
                print(f"✅ 从该源提取了 {count} 个节点")
        except Exception as e:
            print(f"⚠️ 下载/解析失败 {url}: {e}")

    # 去重
    uniq, seen, clash_px, v2_links = [], set(), [], []
    for n in nodes:
        key = (n['s'], n['p'], n.get('u') or n.get('pw'))
        if key not in seen:
            uniq.append(n)
            seen.add(key)

    for i, n in enumerate(uniq):
        nm = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        px = {"name": nm, "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'vless':
            px.update({"type":"vless","uuid":n['u'],"udp":True,"network":n.get('net','tcp')})
            if n['sec'] in ['tls', 'reality']:
                px["tls"] = True
                if n['sn']: px["servername"] = n['sn']
                if n['fp']: px["client-fingerprint"] = n['fp']
            if n['sec'] == 'reality' and n['pbk']:
                px["reality-opts"] = {"public-key": n['pbk'], "short-id": n['sid'] or ""}
            
            l = f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security={n['sec']}&type={n.get('net','tcp')}"
            if n['sn']: l += f"&sni={n['sn']}"
            if n['fp']: l += f"&fp={n['fp']}"
            if n['pbk']: l += f"&pbk={n['pbk']}&sid={n['sid'] or ''}"
            v2_links.append(f"{l}#{nm}")
        
        elif n['t'] == 'hysteria2':
            px.update({"type":"hysteria2","password":n['u'],"sni":n['sn']})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn'] or ''}#{nm}")
        
        elif n['t'] == 'naive':
            px.update({"type":"http","username":n['u'],"password":n['pw'],"tls":True,"sni":n['sn'],"proxy-octet-stream":True})
            v2_links.append(f"http://{n['u']}:{n['pw']}@{n['s']}:{n['p']}#{nm}")

        clash_px.append(px)

    if not clash_px:
        print("❌ 未能提取到任何有效节点，不生成文件。")
        return

    # 写入文件
    conf = {"proxies": clash_px, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [p['name'] for p in clash_px] + ["DIRECT"]}, {"name": "⚡ 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300}], "rules": ["MATCH,🚀 节点选择"]}
    
    with open(os.path.join(OUT_DIR, "clash.yaml"), 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    with open(os.path.join(OUT_DIR, "node.txt"), 'w', encoding='utf-8') as f:
        f.write("\n".join(v2_links))
    with open(os.path.join(OUT_DIR, "sub.txt"), 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(v2_links).encode()).decode())

    print(f"🎉 成功生成文件到 {OUT_DIR} 目录！")
    print(f"📊 统计: VLESS:{len([x for x in uniq if x['t']=='vless'])} | HY2:{len([x for x in uniq if x['t']=='hysteria2'])} | Naive:{len([x for x in uniq if x['t']=='naive'])}")

if __name__ == "__main__":
    main()
