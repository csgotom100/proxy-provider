import yaml
import json
import urllib.request
import socket
import time
import re
import base64
import os
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# --- 配置 ---
TIMEOUT = 10.0           
MAX_THREADS = 50
FILTER_DEAD_NODES = False 
SOURCE_FILE = './urls/manual_json.txt' # 这里放入你所有的在线 JSON/YAML 链接
TEMPLATE_FILE = './templates/clash_template.yaml'
OUTPUT_DIR = './sub'
BEIJING_TZ = timezone(timedelta(hours=8))

os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_node_type(item):
    """根据字典特征智能判断节点协议类型"""
    p_type = str(item.get('type', '')).lower()
    if 'auth' in item or 'hy2' in p_type or 'hysteria2' in p_type: return 'hysteria2'
    if 'uuid' in item or 'vless' in p_type: return 'vless'
    if 'congestion_control' in item or 'juicity' in p_type: return 'juicity'
    if 'proxy' in item and 'https://' in str(item.get('proxy')): return 'socks5' # Naive
    if 'profiles' in item and 'rpcPort' in item: return 'socks5' # Mieru
    return p_type if p_type in ['vless', 'hysteria2', 'juicity', 'socks5', 'ss', 'trojan', 'vmess'] else None

def extract_all_dicts(obj):
    """递归提取 JSON/YAML 中所有的字典对象"""
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
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as res:
            content = res.read().decode('utf-8').strip()
            data = json.loads(content) if (content.startswith('{') or content.startswith('[')) else yaml.safe_load(content)
            
            # 扫描所有可能的字典
            all_dicts = extract_all_dicts(data)
            for item in all_dicts:
                # 1. 寻找服务器地址
                srv = item.get('server') or item.get('add') or item.get('address') or item.get('ipAddress')
                if not srv or str(srv).startswith('127.'): continue
                
                # 2. 寻找端口并清洗 (处理 443-445, 80/tcp 等情况)
                prt = item.get('port') or item.get('server_port') or item.get('listen_port')
                if not prt and ':' in str(srv): 
                    srv, prt = str(srv).rsplit(':', 1)
                if prt:
                    prt = str(prt).split(',')[0].split('-')[0].split('/')[0].strip()
                    if not prt.isdigit(): continue
                else: continue

                # 3. 寻找密钥 (UUID/Password)
                secret = item.get('password') or item.get('uuid') or item.get('auth') or item.get('id')
                if not secret and 'proxy' not in item: continue # Naive 特殊处理

                # 4. 判定协议
                ntype = get_node_type(item)
                if not ntype: continue

                # 5. 构造标准化节点字典
                node = {
                    "name": f"{ntype.upper()}_{srv}",
                    "type": ntype,
                    "server": str(srv).replace('[','').replace(']',''),
                    "port": int(prt),
                    "password": secret if ntype != 'vless' else None,
                    "uuid": secret if ntype == 'vless' else None,
                    "sni": item.get('sni') or item.get('server_name') or item.get('serverName'),
                    "skip-cert-verify": True
                }
                
                # 针对 Reality 特殊处理
                tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
                ry = tls_obj.get('reality') or item.get('reality') or {}
                if ry and isinstance(ry, dict):
                    node["reality"] = {"pbk": ry.get('public_key') or ry.get('publicKey'), "sid": ry.get('short_id') or ry.get('shortId')}
                
                nodes.append(node)
    except Exception as e: print(f"抓取失败 {url}: {e}")
    return nodes

def to_link(p):
    """生成通用节点链接"""
    try:
        name = urllib.parse.quote(p['name'])
        s, prt = p['server'], p['port']
        if p['type'] == 'hysteria2':
            return f"hy2://{p['password']}@{s}:{prt}?insecure=1&sni={p.get('sni','')}#{name}"
        if p['type'] == 'vless':
            base = f"vless://{p['uuid']}@{s}:{prt}?encryption=none&security=reality"
            if p.get('reality'):
                base += f"&pbk={p['reality']['pbk']}&sid={p['reality']['sid']}"
            return f"{base}&sni={p.get('sni','')}#{name}"
        if p['type'] == 'socks5':
            return f"socks5://{p['password']}@{s}:{prt}#{name}"
    except: return None

def main():
    urls = []
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
            urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    unique_nodes = {}
    for url in urls:
        for node in parse_remote(url.strip()):
            key = (node['server'], node['port'], node['type'])
            if key not in unique_nodes: unique_nodes[key] = node

    final_nodes = list(unique_nodes.values())

    # 导出 Clash 订阅
    if os.path.exists(TEMPLATE_FILE):
        with open(TEMPLATE_FILE, 'r', encoding='utf-8') as f:
            tpl = yaml.safe_load(f)
        tpl['proxies'] = final_nodes
        # 自动填充所有组
        p_names = [n['name'] for n in final_nodes]
        for g in tpl.get('proxy-groups', []):
            if 'proxies' in g: g['proxies'].extend(p_names)
        with open(f"{OUTPUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
            yaml.dump(tpl, f, sort_keys=False, allow_unicode=True)

    # 导出 Base64 订阅
    links = [to_link(n) for n in final_nodes if to_link(n)]
    with open(f"{OUTPUT_DIR}/sub.txt", 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())
    
    print(f"✅ 任务完成! 抓取节点: {len(final_nodes)}")

if __name__ == "__main__":
    main()
