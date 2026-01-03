import json, requests, base64, yaml, urllib.parse, os, warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

# --- 配置 ---
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json"
]
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_node_info(item):
    """【抄自参考代码】极致宽容的字段提取逻辑"""
    try:
        if not isinstance(item, dict): return None
        # 1. 服务器提取
        raw_server = item.get('server') or item.get('add') or item.get('address')
        if not raw_server or str(raw_server).startswith('127.'): return None
        
        server_str = str(raw_server).strip()
        server, port = "", ""
        if ']:' in server_str: 
            server, port = server_str.split(']:')[0] + ']', server_str.split(']:')[1]
        elif server_str.startswith('[') and ']' in server_str:
            server, port = server_str, (item.get('port') or item.get('server_port'))
        elif server_str.count(':') == 1:
            server, port = server_str.split(':')
        else:
            server, port = server_str, (item.get('port') or item.get('server_port') or item.get('port_num'))

        if port: port = str(port).split(',')[0].split('-')[0].split('/')[0].strip()
        if not server or not port: return None

        # 2. 密钥提取
        secret = item.get('auth') or item.get('auth_str') or item.get('auth-str') or \
                 item.get('password') or item.get('uuid') or item.get('id')
        if not secret: return None

        # 3. 协议判定
        p_type = str(item.get('type', '')).lower()
        if 'auth' in item or 'hy2' in p_type or 'hysteria2' in p_type: p_type = 'hysteria2'
        elif 'uuid' in item or 'vless' in p_type or 'id' in item: p_type = 'vless'
        else: p_type = 'vless' # 兜底

        # 4. SNI & Reality 信息 (抄自参考代码的 reality-opts 处理)
        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = item.get('servername') or item.get('sni') or tls_obj.get('server_name') or tls_obj.get('sni') or ""
        
        reality_obj = item.get('reality-opts') or tls_obj.get('reality') or item.get('reality') or {}
        if not isinstance(reality_obj, dict): reality_obj = {}
        pbk = reality_obj.get('public-key') or reality_obj.get('public_key') or item.get('public-key') or ""
        sid = reality_obj.get('short-id') or reality_obj.get('short_id') or item.get('short-id') or ""
        
        return {
            "server": server.replace('[','').replace(']',''), "port": int(port), "type": p_type, 
            "sni": sni, "secret": secret, "pbk": pbk, "sid": sid, "raw_server": server_str
        }
    except: return None

def extract_dicts(obj):
    """【抄自参考代码】递归提取所有字典"""
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(extract_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(extract_dicts(i))
    return res

def main():
    raw_nodes_data = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            content = r.text.strip()
            data = json.loads(content) if (content.startswith('{') or content.startswith('[')) else yaml.safe_load(content)
            
            for d in extract_dicts(data):
                node = get_node_info(d)
                if node: raw_nodes_data.append(node)
        except: continue

    # 去重
    unique_configs = []
    seen = set()
    for n in raw_nodes_data:
        config_key = (n['type'], n['server'], n['port'], n['secret'])
        if config_key not in seen:
            unique_configs.append(n); seen.add(config_key)

    # 构造 Clash 格式
    clash_proxies = []
    for i, n in enumerate(unique_configs):
        name = f"{n['type'].upper()}_{n['server'][-5:]}_{i+1}"
        if n['type'] == 'hysteria2':
            clash_proxies.append({
                "name": name, "type": "hysteria2", "server": n['server'], "port": n['port'],
                "password": n['secret'], "tls": True, "sni": n['sni'], "skip-cert-verify": True
            })
        elif n['type'] == 'vless':
            node = {
                "name": name, "type": "vless", "server": n['server'], "port": n['port'],
                "uuid": n['secret'], "tls": True, "udp": True, "servername": n['sni'],
                "network": "tcp", "client-fingerprint": "chrome"
            }
            if n['pbk']:
                node["reality-opts"] = {"public-key": n['pbk'], "short-id": n['sid']}
            clash_proxies.append(node)

    # 生成最终配置
    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [p['name'] for p in clash_proxies]}],
        "rules": ["MATCH,PROXY"]
    }

    with open(f"{OUTPUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    print(f"✅ 成功! 抓取节点总数: {len(clash_proxies)}")

if __name__ == "__main__":
    main()
