import yaml, json, urllib.request, socket, time, re, base64, os, urllib.parse, ssl
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# --- 配置 ---
TIMEOUT = 5.0            # 测速超时（激进些，5秒不通就不要了）
MAX_THREADS = 100        # 增加并发，地毯式扫描需要速度
SOURCE_FILE = './urls/manual_json.txt'
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_tcp_delay(server, port):
    """测速防线：只保留真正活着的节点"""
    start = time.time()
    try:
        sock = socket.create_connection((server, port), timeout=TIMEOUT)
        sock.close()
        return int((time.time() - start) * 1000)
    except: return None

def extract_all_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(extract_all_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(extract_all_dicts(i))
    return res

def parse_uri(uri):
    """正则解析各种原始链接"""
    try:
        name = urllib.parse.unquote(uri.split('#')[-1]) if '#' in uri else "Proxy"
        if uri.startswith('ss://'):
            content = uri[5:].split('#')[0]
            if '@' in content:
                user, server_info = content.split('@')
                method_pass = base64.b64decode(user + '=' * (-len(user) % 4)).decode()
                m, p = method_pass.split(':')
                s, pt = server_info.split(':')
                return {"type":"ss","server":s,"port":int(pt),"cipher":m,"password":p,"name":name}
        elif uri.startswith('vless://') or uri.startswith('hysteria2://') or uri.startswith('hy2://'):
            p_type = "hysteria2" if "hy2" in uri else "vless"
            pattern = r'://(.*)@(.*):(\d+)'
            match = re.search(pattern, uri)
            if match:
                secret, srv, prt = match.groups()
                node = {"type":p_type,"server":srv,"port":int(prt),"name":name}
                if p_type == "vless": node["uuid"] = secret
                else: node["password"] = secret
                # 提取 SNI/PBK
                if '?' in uri:
                    q = urllib.parse.parse_qs(uri.split('?')[1].split('#')[0])
                    if 'sni' in q: node['sni'] = q['sni'][0]
                    if 'pbk' in q: node['reality-opts'] = {"public-key": q['pbk'][0], "short-id": q.get('sid',[''])[0]}
                return node
    except: pass
    return None

def parse_remote(url):
    nodes = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as res:
            raw_content = res.read().decode('utf-8', errors='ignore')
            
            # 1. 尝试作为结构化数据解析
            try:
                data = json.loads(raw_content) if (raw_content.startswith('{') or raw_content.startswith('[')) else yaml.safe_load(raw_content)
                for item in extract_all_dicts(data):
                    srv = item.get('server') or item.get('add') or item.get('address') or item.get('host')
                    prt = item.get('port') or item.get('server_port') or item.get('port_num')
                    sec = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
                    if srv and prt and sec:
                        p_type = str(item.get('type', 'vless')).lower()
                        nodes.append({"server":str(srv),"port":int(str(prt).split(',')[0]),"type":p_type,"uuid":sec if 'vless' in p_type else None, "password":sec if 'vless' not in p_type else None, "sni":item.get('sni')})
            except: pass

            # 2. 尝试作为 Base64 或 纯文本链接扫描
            text_to_scan = raw_content
            if not (raw_content.startswith('{') or 'proxies' in raw_content):
                try: text_to_scan += "\n" + base64.b64decode(raw_content).decode()
                except: pass
            
            uris = re.findall(r'(vless://|ss://|hy2://|hysteria2://)[^\s\'"<>]+', text_to_scan)
            for uri in uris:
                # 重新拼凑完整链接进行解析
                full_uri = re.search(rf'{uri}[^\s\'"<>]+', text_to_scan).group()
                n = parse_uri(full_uri)
                if n: nodes.append(n)
    except: pass
    return nodes

def process_node(n):
    """测速并清洗"""
    delay = get_tcp_delay(n['server'], n['port'])
    if delay:
        n['name'] = f"{n['type'].upper()}_{n['server'][-5:]}_{delay}ms"
        return n
    return None

def main():
    urls = [
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
        "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
        "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    ]
    if os.path.exists(SOURCE_FILE):
        with open(SOURCE_FILE, 'r') as f:
            urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))

    # 地毯式搜刮
    raw_pool = []
    print(f"地毯式搜刮中...")
    with ThreadPoolExecutor(max_workers=20) as exe:
        for results in exe.map(parse_remote, list(set(urls))):
            raw_pool.extend(results)

    # 测速防线
    print(f"正在为 {len(raw_pool)} 个候选节点测速...")
    final_nodes = []
    seen = set()
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
        for n in exe.map(process_node, raw_pool):
            if n:
                key = (n['server'], n['port'])
                if key not in seen:
                    final_nodes.append(n)
                    seen.add(key)

    # 导出
    clash = {"proxies": final_nodes, "proxy-groups": [{"name":"PROXY","type":"select","proxies":[n['name'] for n in final_nodes]}]}
    with open(f"{OUTPUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(clash, f, sort_keys=False, allow_unicode=True)
    
    print(f"✅ 抓取完成! 存活节点: {len(final_nodes)}")

if __name__ == "__main__":
    main()
