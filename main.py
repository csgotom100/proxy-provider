import json, urllib.request, yaml, os, ssl, warnings, re, time
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")

OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

# --- 🎯 样板处理器仓库 ---

class ProtocolHandlers:
    @staticmethod
    def vless_singbox(d):
        """适配样板 1：VLESS Sing-box (Reality)"""
        try:
            tls = d.get('tls', {})
            real = tls.get('reality', {})
            return {
                "s": d.get('server'),
                "p": int(d.get('server_port')),
                "u": d.get('uuid'),
                "t": "vless",
                "sn": tls.get('server_name', 'itunes.apple.com'),
                "pbk": real.get('public_key'),
                "sid": real.get('short_id')
            }
        except: return None

    @staticmethod
    def hy2_native(d):
        """适配样板 2：Hysteria2 Native (auth_str)"""
        try:
            s_raw = d.get('server', '')
            # 处理 62.210.127.177:23880 连写格式
            host, port = s_raw.rsplit(':', 1)
            return {
                "s": host.replace('[','').replace(']',''),
                "p": int(port),
                "u": d.get('auth_str'),
                "t": "hysteria2",
                "sn": d.get('server_name', 'bing.com')
            }
        except: return None

    @staticmethod
    def naive_alvin(d):
        """适配样板 3：NaiveProxy Alvin 专用字符串格式"""
        if 'proxy' in d and 'https://' in str(d.get('proxy')):
            m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', d.get('proxy'))
            if m:
                return {
                    "s": m.group(3), "p": int(m.group(4)), "u": m.group(1),
                    "pass": m.group(2), "t": "naive", "sn": m.group(3)
                }
        return None

# --- 🛠️ 核心解析引擎 ---

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
    
    extracted_nodes = []
    print(f"📂 开始精准解析 {len(urls)} 个源地址...")

    for url in urls:
        # 协议路由探测
        ptype = 'vless' if '/vless/' in url or '/xray/' in url else \
                'hy2' if '/hysteria2/' in url or '/ipp/hy' in url else \
                'naive' if '/naiveproxy/' in url else 'general'
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
                text = resp.read().decode('utf-8', errors='ignore')
                data = json.loads(text) if '{' in text else yaml.safe_load(text)
                
                for d in find_dicts(data):
                    node = None
                    if ptype == 'vless': node = ProtocolHandlers.vless_singbox(d)
                    elif ptype == 'hy2': node = ProtocolHandlers.hy2_native(d)
                    elif ptype == 'naive': node = ProtocolHandlers.naive_alvin(d)
                    
                    # 如果路由解析失败，尝试所有样板保底
                    if not node:
                        node = ProtocolHandlers.hy2_native(d) or \
                               ProtocolHandlers.vless_singbox(d) or \
                               ProtocolHandlers.naive_alvin(d)
                    
                    if node: extracted_nodes.append(node)
        except: continue

    # 去重逻辑
    uniq, seen = [], set()
    for n in extracted_nodes:
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    # 转换 Clash 格式
    clash_px = []
    for i, n in enumerate(uniq):
        name = f"Node_{i+1}_{n['t'].upper()}_{n['s'].split('.')[-1]}"
        px = {"name": name, "type": n['t'], "server": n['s'], "port": n['p'], "skip-cert-verify": True}
        
        if n['t'] == 'hysteria2':
            px.update({"password": n['u'], "sni": n['sn']})
        elif n['t'] == 'vless':
            px.update({"uuid": n['u'], "tls": True, "servername": n['sn']})
            if n.get('pbk'):
                px.update({"network": "tcp", "reality-opts": {"public-key": n['pbk'], "short-id": n.get('sid','')}})
        elif n['t'] == 'naive':
            px.update({"username": n['u'], "password": n['pass'], "proxy-octet-stream": True})
            
        clash_px.append(px)

    # 输出 YAML
    conf = {
        "proxies": clash_px,
        "proxy-groups": [{"name": "🚀 自动选择", "type": "url-test", "proxies": [p['name'] for p in clash_px], "url": "http://www.gstatic.com/generate_204", "interval": 300}],
        "rules": ["MATCH,🚀 自动选择"]
    }

    with open(f"{OUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    
    print(f"✅ 精准汇总完成！节点数: {len(clash_px)}")

if __name__ == "__main__":
    main()
