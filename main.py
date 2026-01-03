import json, urllib.request, yaml, os, ssl, warnings, re, base64, time
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")

# --- 1. 基础配置 ---
OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    """获取国旗 Emoji"""
    try:
        clean_ip = ip.replace('[','').replace(']','')
        url = f"http://ip-api.com/json/{clean_ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read().decode())
            code = data.get('countryCode', 'UN')
            return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🏳️"

def get_node(item):
    """多协议适配解析器"""
    try:
        if not isinstance(item, dict): return None
        
        # 1. 尝试识别 NaiveProxy (通常包含 proxy 字段且格式为 https://)
        if 'proxy' in item and 'https://' in str(item.get('proxy')):
            p_str = item.get('proxy')
            auth, addr = p_str.split('://')[1].split('@')
            u, pwd = auth.split(':')
            s, port = addr.split(':')
            return {"s": s, "p": int(port), "t": "naive", "u": u, "pass": pwd, "sn": s}

        # 2. 提取通用字段
        s = item.get('server') or item.get('add') or item.get('address')
        p = item.get('port') or item.get('server_port') or item.get('listen_port')
        u = item.get('uuid') or item.get('password') or item.get('id') or item.get('auth') or item.get('user_id')
        
        if not (s and p): return None
        s, p = str(s).replace('[','').replace(']',''), int(str(p).split(',')[0].strip())
        t = str(item.get('type', '')).lower()

        # 3. 判定协议类型
        if 'juicity' in t or 'juicity' in str(item):
            return {"s": s, "p": p, "t": "juicity", "u": str(u), "sn": item.get('sni', s)}
        
        nt = 'hysteria2' if ('hy2' in t or 'hysteria2' in t or 'auth' in item) else 'vless'
        tls = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sn = item.get('sni') or item.get('servername') or tls.get('server_name') or ""
        
        node = {"s": s, "p": p, "t": nt, "u": str(u), "sn": sn}
        ry = item.get('reality-opts') or item.get('reality') or tls.get('reality') or {}
        if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
            node["pbk"], node["sid"] = (ry.get('public-key') or ry.get('publicKey')), (ry.get('short-id') or ry.get('shortId') or "")
        return node
    except: return None

def ext_dicts(obj):
    """深度递归提取所有字典"""
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(ext_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(ext_dicts(i))
    return res

def main():
    # --- 只读取 manual_json.txt ---
    if not os.path.exists(MANUAL_FILE):
        print(f"❌ 错误: 找不到文件 {MANUAL_FILE}")
        return

    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = list(set(re.findall(r'https?://[^\s\'"\[\],]+', f.read())))
    
    print(f"📂 已读取 {len(urls)} 个源地址，准备开始抓取...")

    raw_nodes = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                # 兼容 JSON 和 YAML
                try:
                    data = json.loads(content)
                    for d in ext_dicts(data):
                        n = get_node(d)
                        if n: raw_nodes.append(n)
                except:
                    data = yaml.safe_load(content)
                    if 'proxies' in data:
                        for p in data['proxies']:
                            n = get_node(p)
                            if n: raw_nodes.append(n)
        except Exception as e:
            print(f"⚠️ 无法读取源 {url}: {e}")

    # 去重
    uniq, seen = [], set()
    for n in raw_nodes:
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    clash_px = []
    bj_time = datetime.now(timezone(timedelta(hours=8))).strftime("%m-%d %H:%M")
    
    print(f"🔍 抓取到 {len(uniq)} 个有效节点，正在查询地理位置...")
    for i, n in enumerate(uniq):
        flag = get_geo(n['s'])
        name = f"{flag} {n['t'].upper()}_{n['s'].split('.')[-1]}_{i+1}"
        
        # 针对 Clash Meta 的协议适配
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        if n['t'] == 'hysteria2':
            px.update({"password": n['u'], "sni": n['sn']})
        elif n['t'] == 'juicity':
            px.update({"uuid": n['u'], "sni": n['sn'], "conntrack": True})
