import yaml
import json
import urllib.request
import re
import base64
import os
import urllib.parse
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# --- 配置 ---
TIMEOUT = 12.0           
MAX_THREADS = 50
SOURCE_FILE = './urls/manual_json.txt'
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_node_type(item):
    """极致容错的协议识别"""
    # 显式定义的 type
    p_type = str(item.get('type', '')).lower()
    if p_type in ['vless', 'hysteria2', 'juicity', 'trojan', 'ss', 'shadowsocks', 'vmess']:
        return 'ss' if p_type == 'shadowsocks' else p_type
    
    # 根据特征识别
    if 'auth' in item or 'auth-str' in item: return 'hysteria2'
    if 'uuid' in item: return 'vless'
    if 'cipher' in item or 'method' in item: return 'ss'
    if 'password' in item and not p_type: return 'trojan' # 默认尝试作为 trojan
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
        headers = {'User-Agent': 'Mozilla/5.0'}
        # 禁用 SSL 验证以应对部分证书过期的源
        import ssl
        context = ssl._create_unverified_context()
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15, context=context) as res:
            content = res.read().decode('utf-8').strip()
            # 自动识别 YAML/JSON
            try:
                data = json.loads(content) if (content.startswith('{') or content.startswith('[')) else yaml.safe_load(content)
            except: return []

            all_dicts = extract_all_dicts(data)
            for item in all_dicts:
                # 提取服务器地址
                srv = item.get('server') or item.get('add') or item.get('address') or item.get('ipAddress')
                if not srv or str(srv).startswith('127.') or srv == 'localhost': continue
                
                # 提取端口 (增加 port_num 适配)
                prt = item.get('port') or item.get('server_port') or item.get('listen_port') or item.get('port_num')
                if not prt and ':' in str(srv):
                    srv_parts = str(srv).rsplit(':', 1)
                    srv, prt = srv_parts[0], srv_parts[1]
                
                if not prt: continue
                prt = str(prt).split(',')[0].split('-')[0].split('/')[0].strip()
                if not prt.isdigit(): continue

                # 提取协议
                ntype = get_node_type(item)
                if not ntype: continue

                # 提取密钥 (id, uuid, password, auth)
                secret = item.get('password') or item.get('uuid') or item.get('auth') or item.get('id') or item.get('auth-str')
                if not secret and ntype != 'socks5': continue

                node = {
                    "name": f"{ntype.upper()}_{srv}_{prt}",
                    "type": ntype,
                    "server": str(srv).replace('[','').replace(']',''),
                    "port": int(prt),
                    "sni": item.get('sni') or item.get('server_name') or item.get('serverName') or item.get('peer'),
                    "skip-cert-verify": True
                }

                # 协议细节填充
                if ntype == 'vless': 
                    node["uuid"] = secret
                else: 
                    node["password"] = secret

                if ntype == 'ss':
                    node["cipher"] = item.get('cipher') or item.get('method') or 'aes-256-gcm'

                # Reality 参数
                tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
                ry = item.get('reality') or tls_obj.get('reality') or item.get('reality-opts') or {}
                if ry and isinstance(ry, dict):
                    node["reality-opts"] = {
                        "public-key": ry.get('public-key') or ry.get('publicKey') or ry.get('public_key'),
                        "short-id": ry.get('short-id') or ry.get('shortId') or ry.get('short_id')
                    }
                    node["network"] = item.get('network', 'tcp')
                
                nodes.append(node)
    except: pass
    return nodes

def to_link(p):
    """导出通用链接"""
    try:
        name = urllib.parse.quote(p['name'])
        s, prt = p['server'], p['port']
        if p['type'] == 'hysteria2':
            return f"hy2://{p['password']}@{s}:{prt}?insecure=1&sni={p.get('sni','')}#{name}"
        if p['type'] == 'vless':
            link = f"vless://{p['uuid']}@{s}:{prt}?encryption=none&security=reality&sni={p.get('sni','')}"
            if p.get('reality-opts'):
                link += f"&pbk={p['reality-opts']['public-key']}&sid={p['reality-opts']['short-id']}"
            return f"{link}#{name}"
        if p['type'] == 'ss':
            auth = base64.b64encode(f"{p['cipher']}:{p['password']}".encode()).decode()
            return f"ss://{auth}@{s}:{prt}#{name}"
    except: return None

def main():
    # 1. 自动注入 Alvin9999 的源
    fixed_urls = [
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
        "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json"
    ]
    
    # 读取用户文件中的 URL
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
            fixed_urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))
    
    unique_nodes = {}
    print(f"开始抓取 {len(fixed_urls)} 个源...")
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = executor.map(parse_remote, fixed_urls)
        for nodes in results:
            for node in nodes:
                key = (node['server'], node['port'], node['type'], node.get('uuid') or node.get('password'))
                if key not in unique_nodes:
                    unique_nodes[key] = node

    final_list = list(unique_nodes.values())
    
    # 导出 Clash
    clash_out = {"proxies": final_list, "proxy-groups": [{"name":"PROXY","type":"select","proxies":[n['name'] for n in final_list]}]}
    with open(f"{OUTPUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(clash_out, f, sort_keys=False, allow_unicode=True)

    # 导出链接
    links = [to_link(n) for n in final_list if to_link(n)]
    with open(f"{OUTPUT_DIR}/sub.txt", 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())
    
    print(f"✅ 抓取完成! 总节点数: {len(final_list)}")

if __name__ == "__main__":
    main()
