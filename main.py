import yaml, json, urllib.request, socket, time, re, base64, os, urllib.parse
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# --- 配置 ---
TIMEOUT = 10.0           
MAX_THREADS = 40
SOURCE_FILE = './urls/manual_json.txt'
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)
GEO_CACHE = {}

def get_location(ip):
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
        with urllib.request.urlopen(url, timeout=3) as res:
            data = json.loads(res.read().decode())
            loc = data.get('country', '未知')
            GEO_CACHE[ip] = loc
            return loc
    except: return "未知"

def decode_base64(data):
    """通用的 Base64 解码，处理填充问题"""
    data = data.replace('-', '+').replace('_', '/')
    missing_padding = len(data) % 4
    if missing_padding: data += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except: return ""

def parse_uri(uri):
    """解析 ss:// vless:// vmess:// 等链接"""
    try:
        if uri.startswith('ss://'):
            # 处理 ss://base64(method:pass)@ip:port#name
            content = uri[5:].split('#')[0]
            if '@' in content:
                user_info, server_info = content.split('@')
                method_pass = decode_base64(user_info)
                method, password = method_pass.split(':')
                server, port = server_info.split(':')
                return {"type": "ss", "server": server, "port": int(port), "cipher": method, "password": password}
        
        elif uri.startswith('vless://'):
            # vless://uuid@ip:port?params#name
            pattern = r'vless://(.*)@(.*):(\d+)\?(.*)#(.*)'
            match = re.match(pattern, uri)
            if match:
                uuid, srv, prt, params, name = match.groups()
                query = urllib.parse.parse_qs(params)
                node = {"type": "vless", "server": srv, "port": int(prt), "uuid": uuid, "name": urllib.parse.unquote(name)}
                if 'sni' in query: node['sni'] = query['sni'][0]
                if 'pbk' in query: node['reality-opts'] = {"public-key": query['pbk'][0], "short-id": query.get('sid', [''])[0]}
                return node
    except: pass
    return None

def extract_all_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(extract_all_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(extract_all_dicts(i))
    return res

def parse_remote(url):
    nodes = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=12) as res:
            content = res.read().decode('utf-8', errors='ignore').strip()
            
            # 1. 尝试识别为 Base64 订阅链接 (如 https://.../sub?clash=1)
            if not (content.startswith('{') or content.startswith('proxies') or content.startswith('outbounds')):
                decoded = decode_base64(content)
                if decoded:
                    for line in decoded.splitlines():
                        n = parse_uri(line.strip())
                        if n: nodes.append(n)
            
            # 2. 尝试识别为 JSON/YAML
            data = json.loads(content) if (content.startswith('{') or content.startswith('[')) else yaml.safe_load(content)
            if data:
                for item in extract_all_dicts(data):
                    srv = item.get('server') or item.get('add') or item.get('address')
                    prt = item.get('port') or item.get('server_port')
                    if not srv or not prt: continue
                    
                    ntype = str(item.get('type', '')).lower()
                    if not ntype:
                        if 'auth' in item: ntype = 'hysteria2'
                        elif 'uuid' in item: ntype = 'vless'
                        else: continue
                    
                    node = {"server": str(srv), "port": int(str(prt).split(',')[0]), "type": ntype}
                    # 密钥填充
                    secret = item.get('password') or item.get('uuid') or item.get('auth') or item.get('id')
                    if ntype == 'vless': node["uuid"] = secret
                    else: node["password"] = secret
                    
                    # Reality 补充
                    ry = item.get('reality') or item.get('reality-opts')
                    if ry: node["reality-opts"] = {"public-key": ry.get('public-key') or ry.get('publicKey'), "short-id": ry.get('short-id') or ry.get('shortId')}
                    nodes.append(node)
    except: pass
    return nodes

def main():
    # 扩展抓取源：增加 Alvin9999 的 Base64 订阅地址
    urls = [
        "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
        "https://raw.githubusercontent.com/Alvin9999/PAC/master/backup/img/1/2/ipp/vless/1/config.json",
        # 你可以添加更多的纯文本/Base64 订阅链接到这里
    ]
    
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r') as f:
            urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))

    all_raw_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
        for nodes in exe.map(parse_remote, urls):
            all_raw_nodes.extend(nodes)

    # 去重并进行地域识别
    unique_list = []
    seen = set()
    print("正在进行地域识别与去重...")
    for n in all_raw_nodes:
        key = (n['server'], n['port'])
        if key not in seen:
            loc = get_location(n['server'])
            n['name'] = f"[{loc}] {n['type'].upper()}_{str(n['server'])[-4:]}"
            unique_list.append(n)
            seen.add(key)

    clash_config = {
        "proxies": unique_list,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [n['name'] for n in unique_list], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 节点切换", "type": "select", "proxies": ["🚀 自动选择"] + [n['name'] for n in unique_list]}
        ],
        "rules": ["MATCH,🔰 节点切换"]
    }

    with open(f"{OUTPUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, sort_keys=False, allow_unicode=True)
    
    print(f"✅ 完成! 当前总节点数: {len(unique_list)}")

if __name__ == "__main__":
    main()
