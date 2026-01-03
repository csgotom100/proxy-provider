import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
OUT_DIR, MANUAL_FILE = './sub', './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def handle_vless(d):
    """严格按照提供的 JSON 结构解析 VLESS/Reality"""
    try:
        # 基础字段提取
        s = d.get('server') or d.get('add')
        p = d.get('server_port') or d.get('port')
        u = d.get('uuid') or d.get('id')
        if not (s and u and p): return None

        # 传输层
        net = d.get('transport', {}).get('type') or d.get('net', 'tcp')
        sec, sn, pbk, sid, fp = 'none', None, None, None, None

        # 适配 sing-box 风格
        tls = d.get('tls', {})
        if tls.get('enabled'):
            sec = 'tls'
            sn = tls.get('server_name')
            fp = tls.get('utls', {}).get('fingerprint')
            ry = tls.get('reality', {})
            if ry.get('enabled'):
                sec = 'reality'
                pbk = ry.get('public_key')
                sid = ry.get('short_id')

        # 适配 xray 风格 (作为补充)
        ss = d.get('streamSettings', {})
        if ss:
            net = ss.get('network') or net
            sec = ss.get('security') or sec
            rl = ss.get('realitySettings')
            if rl:
                sn = rl.get('serverName') or sn
                pbk = rl.get('publicKey') or pbk
                sid = rl.get('shortId') or sid
                fp = rl.get('fingerprint') or fp

        return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","net":net,"sec":sec,"sn":sn,"pbk":pbk,"sid":sid,"fp":fp}
    except: return None

def handle_hy2(d):
    """修复 Hysteria2 解析，确保不漏掉独立配置"""
    try:
        if d.get('type') != 'hysteria2' and d.get('protocol') != 'hysteria2': return None
        s = d.get('server') or d.get('add')
        p = d.get('server_port') or d.get('port')
        u = d.get('auth') or d.get('password') or d.get('auth_str')
        if not (s and u): return None
        
        # 处理 server 字段带端口的情况
        host = str(s).split(':')[0].replace('[','').replace(']','')
        port = p or (s.split(':')[1] if ':' in str(s) else 443)
        return {"s":host,"p":int(port),"u":str(u),"t":"hysteria2","sn":d.get('tls',{}).get('server_name') or d.get('sni')}
    except: return None

def handle_naive(d):
    """NaiveProxy 专用匹配逻辑，不干扰其他协议"""
    try:
        proxy_str = d.get('proxy', '')
        if 'https://' in proxy_str:
            m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', proxy_str)
            if m:
                return {"u":m.group(1),"pw":m.group(2),"s":m.group(3),"p":int(m.group(4)),"t":"naive","sn":m.group(3)}
    except: return None

def find_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values(): yield from find_dicts(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_dicts(i)

def main():
    if not os.path.exists(MANUAL_FILE): return
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    nodes = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(raw) if '{' in raw else yaml.safe_load(raw)
                for d in find_dicts(data):
                    # 各协议解析器完全独立执行
                    n = handle_vless(d) or handle_hy2(d) or handle_naive(d)
                    if n: nodes.append(n)
        except: continue
    
    uniq, seen, clash_px, v2_links = [], set(), [], []
    for n in nodes:
        key = (n['s'], n['p'], n.get('u') or n.get('pw'))
        if key not in seen: uniq.append(n); seen.add(key)

    for i, n in enumerate(uniq):
        nm = f"{i+1:02d}_{n['t'].upper()}_{str(n['s']).split('.')[-1]}"
        px = {"name": nm, "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'vless':
            px.update({"type":"vless","uuid":n['u'],"udp":True,"network":n['net']})
            if n['sec'] in ['tls', 'reality']:
                px["tls"] = True
                if n['sn']: px["servername"] = n['sn']
                if n['fp']: px["client-fingerprint"] = n['fp']
            if n['sec'] == 'reality' and n['pbk']:
                px["reality-opts"] = {"public-key": n['pbk'], "short-id": n['sid'] or ""}
            # 生成你验证通过的链接格式
            l = f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security={n['sec']}&type={n['net']}"
            if n['sn']: l += f"&sni={n['sn']}"; 
            if n['fp']: l += f"&fp={n['fp']}";
            if n['pbk']: l += f"&pbk={n['pbk']}&sid={n['sid'] or ''}"
            v2_links.append(f"{l}#{nm}")
        
        elif n['t'] == 'hysteria2':
            px.update({"type":"hysteria2","password":n['u'],"sni":n['sn']})
            v2_links.append(f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn'] or ''}#{nm}")
        
        elif n['t'] == 'naive':
            px.update({"type":"http","username":n['u'],"password":n['pw'],"tls":True,"sni":n['sn'],"proxy-octet-stream":True})
            v2_links.append(f"http://{n['u']}:{n['pw']}@{n['s']}:{n['p']}#{nm}")

        clash_px.append(px)

    # 保持最简洁的 Clash 规则，防止报错
    conf = {"proxies": clash_px, "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + [p['name'] for p in clash_px] + ["DIRECT"]}, {"name": "⚡ 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300}], "rules": ["MATCH,🚀 节点选择"]}
    with open(f"{OUT_DIR}/clash.yaml",'w',encoding='utf-8') as f: yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    with open(f"{OUT_DIR}/node.txt",'w',encoding='utf-8') as f: f.write("\n".join(v2_links))
    with open(f"{OUT_DIR}/sub.txt",'w',encoding='utf-8') as f: f.write(base64.b64encode("\n".join(v2_links).encode()).decode())
    print(f"✅ 完成! Naive:{len([x for x in uniq if x['t']=='naive'])} | HY2:{len([x for x in uniq if x['t']=='hysteria2'])} | VLESS:{len([x for x in uniq if x['t']=='vless'])}")

if __name__ == "__main__": main()
