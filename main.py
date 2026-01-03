import json, urllib.request, yaml, os, ssl, warnings, re, base64, time
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")

# --- 1. 配置 ---
OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
# 如果你的客户端报错，请在这里剔除 'naive' 或 'juicity'
SUPPORTED_TYPES = ['vless', 'hysteria2', 'shadowsocks', 'trojan'] 

os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    try:
        clean_ip = ip.replace('[','').replace(']','')
        if not re.match(r'^\d', clean_ip) and not ':' in clean_ip: return "🏳️"
        url = f"http://ip-api.com/json/{clean_ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            code = json.loads(r.read().decode()).get('countryCode', 'UN')
            return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🏳️"

def parse_strict(d):
    """严格解析 JSON"""
    try:
        if not isinstance(d, dict): return None
        
        # 处理 Naive 特殊字符串
        if 'proxy' in d and 'https://' in str(d.get('proxy')):
            m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d.get('proxy'))
            if m: return {"s": m.group(3), "p": int(m.group(4)), "t": "naive", "u": m.group(1), "pass": m.group(2), "sn": m.group(3)}

        # 基础字段提取
        s_raw = d.get('server') or d.get('add') or d.get('address')
        p = d.get('port') or d.get('server_port') or d.get('listen_port')
        u = d.get('uuid') or d.get('password') or d.get('id') or d.get('auth') or d.get('user_id')
        
        if not (s_raw and u): return None
        
        if ':' in str(s_raw) and not p:
            parts = str(s_raw).split(':')
            s, p = "".join(parts[:-1]).replace('[','').replace(']',''), parts[-1]
        else:
            s, p = str(s_raw).replace('[','').replace(']',''), p

        t_raw = str(d.get('type', '')).lower()
        if 'juicity' in t_raw or 'juicity' in d: t = 'juicity'
        elif 'hy' in t_raw or 'hysteria2' in t_raw or 'auth' in d: t = 'hysteria2'
        else: t = 'vless'

        node = {"s": s, "p": int(p), "u": str(u), "t": t}
        tls = d.get('tls', {}) if isinstance(d.get('tls'), dict) else {}
        node["sn"] = d.get('sni') or d.get('servername') or tls.get('server_name') or ""
        
        ry = d.get('reality-opts') or d.get('reality') or tls.get('reality') or {}
        if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
            node["pbk"], node["sid"] = (ry.get('public-key') or ry.get('publicKey')), (ry.get('short-id') or ry.get('shortId') or "")
        return node
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
        urls = list(set(re.findall(r'https?://[^\s\'"\[\],]+', f.read())))
    
    all_nodes = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
                text = resp.read().decode('utf-8', errors='ignore')
                try: data = json.loads(text)
                except: data = yaml.safe_load(text)
                if data:
                    for d in find_dicts(data):
                        n = parse_strict(d)
                        if n: all_nodes.append(n)
        except: continue

    uniq, seen = [], set()
    for n in all_nodes:
        # --- 增加过滤逻辑：只保留受支持的协议 ---
        if n['t'] not in SUPPORTED_TYPES: continue
        
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    clash_px = []
    bj_time = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")
    
    for i, n in enumerate(uniq):
        flag = get_geo(n['s'])
        name = f"{flag} {n['t'].upper()}_{n['s'].split('.')[-1]}_{i+1}"
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'hysteria2':
            px.update({"password": n['u'], "sni": n['sn']})
        elif n['t'] == 'vless':
            px.update({"uuid": n['u'], "tls": True, "servername": n['sn']})
            if "pbk" in n:
                px.update({"network": "tcp", "reality-opts": {"public-key": n['pbk'], "short-id": n['sid']}})
        
        clash_px.append(px)
        if i % 10 == 0: time.sleep(0.5)

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
    
    print(f"✅ 解析完成! 已过滤不支持的协议，剩余节点数: {len(clash_px)}")

if __name__ == "__main__":
    main()
