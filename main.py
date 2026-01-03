import yaml, json, urllib.request, socket, time, re, base64, os, urllib.parse
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# --- 配置 ---
TIMEOUT = 10.0           
MAX_THREADS = 40
SOURCE_FILE = './urls/manual_json.txt'
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 缓存地理位置，减少重复请求
GEO_CACHE = {}

def get_location(ip):
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        # 使用 ip-api 的免费接口
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
        with urllib.request.urlopen(url, timeout=5) as res:
            data = json.loads(res.read().decode())
            loc = data.get('country', '未知')
            GEO_CACHE[ip] = loc
            return loc
    except:
        return "未知"

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
            content = res.read().decode('utf-8', errors='ignore')
            data = json.loads(content) if (content.startswith('{') or content.startswith('[')) else yaml.safe_load(content)
            
            for item in extract_all_dicts(data):
                srv = item.get('server') or item.get('add') or item.get('address') or item.get('ipAddress')
                prt = item.get('port') or item.get('server_port') or item.get('listen_port')
                if not srv or not prt or str(srv).startswith('127.'): continue

                # 判定协议并提取 ID
                secret = item.get('password') or item.get('uuid') or item.get('auth') or item.get('id')
                p_type = str(item.get('type', '')).lower()
                
                if 'auth' in item or 'hy2' in p_type: ntype = 'hysteria2'
                elif 'uuid' in item or 'vless' in p_type: ntype = 'vless'
                elif 'cipher' in item or 'method' in item: ntype = 'ss'
                else: continue

                # 获取地理位置并美化名称
                loc = get_location(srv)
                node_name = f"[{loc}] {ntype.upper()}_{srv[-4:]}" # 取IP后四位防止重名

                node = {
                    "name": node_name, "type": ntype, "server": str(srv),
                    "port": int(str(prt).split(',')[0]), "skip-cert-verify": True
                }
                
                if ntype == 'vless': node["uuid"] = secret
                else: node["password"] = secret

                # 特殊参数处理
                sni = item.get('sni') or item.get('server_name')
                if sni: node["sni"] = sni
                
                ry = item.get('reality') or item.get('reality-opts')
                if ry: node["reality-opts"] = {"public-key": ry.get('public-key') or ry.get('publicKey'), "short-id": ry.get('short-id') or ry.get('shortId')}
                
                nodes.append(node)
    except: pass
    return nodes

def main():
    # 基础抓取源
    urls = [
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
        "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/1/config.json"
    ]
    
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r') as f:
            urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))

    all_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
        for nodes in exe.map(parse_remote, urls):
            all_nodes.extend(nodes)

    # 去重
    unique_list = []
    seen = set()
    for n in all_nodes:
        key = (n['server'], n['port'])
        if key not in seen:
            unique_list.append(n); seen.add(key)

    # 构造 Clash 完整配置
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
    
    print(f"✅ 完成! 抓取到 {len(unique_list)} 个去重节点。")

if __name__ == "__main__":
    main()
