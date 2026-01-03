import json, urllib.request, yaml, os, ssl, warnings, re, base64, time
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")

OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    try:
        clean_ip = ip.replace('[','').replace(']','')
        if not re.match(r'^\d|[:a-fA-F]', clean_ip): return "🏳️"
        url = f"http://ip-api.com/json/{clean_ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read().decode())
            return "".join(chr(ord(c) + 127397) for c in data.get('countryCode', 'UN').upper())
    except: return "🏳️"

def get_node(item):
    """针对 Alvin9999 源的深度定制解析"""
    try:
        if not isinstance(item, dict): return None
        
        # --- 1. 深度适配 NaiveProxy ---
        if 'proxy' in item and 'https://' in str(item.get('proxy')):
            p_str = item.get('proxy')
            # 格式: https://user:pass@domain:port
            match = re.search(r'https://(.*):(.*)@(.*):(\d+)', p_str)
            if match:
                u, pwd, s, port = match.groups()
                return {"s": s, "p": int(port), "t": "naive", "u": u, "pass": pwd, "sn": s}

        # --- 2. 深度适配 Juicity ---
        if 'server' in item and ('uuid' in item or 'user_id' in item):
            s_field = item.get('server', '')
            if ':' in s_field:
                s, port = s_field.split(':')
                u = item.get('uuid') or item.get('user_id')
                return {"s": s, "p": int(port), "t": "juicity", "u": str(u), "sn": item.get('sni', s)}

        # --- 3. 深度适配 Hysteria2 (Alvin 专用字段) ---
        if 'server' in item and 'auth' in item:
            s_field = item.get('server', '')
            if ':' in s_field:
                s, port = s_field.split(':')
                return {"s": s, "p": int(port), "t": "hysteria2", "u": item.get('auth'), "sn": item.get('sni', s)}

        # --- 4. 标准 VLESS/Xray 格式 ---
        s = item.get('server') or item.get('add') or item.get('address')
        p = item.get('port') or item.get('server_port')
        u = item.get('uuid') or item.get('id')
        if s and p and u:
            t = str(item.get('type', 'vless')).lower()
            sn = item.get('sni') or item.get('servername') or ""
            node = {"s": str(s), "p": int(p), "t": t if t != 'vless' else 'vless', "u": str(u), "sn": sn}
            # Reality 支持
            tls = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
            ry = item.get('reality-opts') or item.get('reality') or tls.get('reality') or {}
            if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
                node["pbk"] = ry.get('public-key') or ry.get('publicKey')
                node["sid"] = ry.get('short-id') or ry.get('shortId') or ""
            return node
    except: pass
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
    if not os.path.exists(MANUAL_FILE):
        print(f"❌ 找不到文件: {MANUAL_FILE}")
        return

    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = list(set(re.findall(r'https?://[^\s\'"\[\],]+', f.read())))
    
    print(f"📂 读取到 {len(urls)} 个地址，正在深度扫描内容...")

    raw_nodes = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                raw_data = resp.read().decode('utf-8', errors='ignore')
                # 尝试作为 JSON 递归提取
                try:
                    data = json.loads(raw_data)
                    for d in ext_dicts(data):
                        n = get_node(d)
                        if n: raw_nodes.append(n)
                except:
                    # 尝试作为 YAML 提取
                    data = yaml.safe_load(raw_data)
                    if isinstance(data, dict) and 'proxies' in data:
                        for p in data['proxies']:
                            n = get_node(p)
                            if n: raw_nodes.append(n)
        except Exception as e:
            print(f"⚠️ 跳过无法访问的源: {url}")

    # 深度去重
    uniq, seen = [], set()
    for n in raw_nodes:
        key = (n['s'], n['p'], n['u'])
        if key not in seen: uniq.append(n); seen.add(key)

    clash_px = []
    bj_time = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")
    
    for i, n in enumerate(uniq):
        flag = get_geo(n['s'])
        name = f"{flag} {n['t'].upper()}_{n['s'].split('.')[-1]}_{i+1}"
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        # 协议细节填充
        if n['t'] == 'hysteria2': px.update({"password": n['u'], "sni": n['sn']})
        elif n['t'] == 'juicity': px.update({"uuid": n['u'], "sni": n['sn'], "conntrack": True})
        elif n['t'] == 'naive': px.update({"username": n['u'], "password": n['pass'], "proxy-octet-stream": True})
        elif n['t'] == 'vless':
            px.update({"uuid": n['u'], "tls": True, "servername": n['sn']})
            if "pbk" in n: px.update({"network": "tcp", "reality-opts": {"public-key": n['pbk'], "short-id": n['sid']}})
        
        clash_px.append(px)
        if i % 15 == 0: time.sleep(1)

    # 生成最终配置
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
    
    print(f"✅ 抓取完成! 成功解析节点: {len(clash_px)}")

if __name__ == "__main__":
    main()
