import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")

# --- 1. 配置源 ---
FIXED_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ip/singbox/2/config.json"
]

MANUAL_FILE = './urls/manual_json.txt'
OUTPUT_DIR = './sub'
os.makedirs(OUTPUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

# --- 2. 解析函数 ---
def get_node_info(item):
    try:
        if not isinstance(item, dict): return None
        srv = item.get('server') or item.get('add') or item.get('address')
        if not srv or str(srv).startswith('127.'): return None
        port = item.get('port') or item.get('server_port') or item.get('port_num')
        if not port and ':' in str(srv): srv, port = str(srv).rsplit(':', 1)
        pwd = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
        if not srv or not port or not pwd: return None

        srv = str(srv).replace('[','').replace(']','')
        port = int(str(port).split(',')[0].strip())
        t = str(item.get('type', '')).lower()
        ntype = 'hysteria2' if ('hy2' in t or 'hysteria2' in t or 'auth' in item) else 'vless'

        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = item.get('sni') or item.get('servername') or tls_obj.get('server_name') or ""
        
        node = {"server": srv, "port": port, "type": ntype, "secret": str(pwd), "sni": sni}
        ry = item.get('reality-opts') or item.get('reality') or tls_obj.get('reality') or {}
        if isinstance(ry, dict) and (ry.get('public-key') or ry.get('publicKey')):
            node["pbk"] = ry.get('public-key') or ry.get('publicKey')
            node["sid"] = ry.get('short-id') or ry.get('shortId') or ""
        return node
    except: return None

def extract_dicts(obj):
    res = []
    if isinstance(obj, dict):
        res.append(obj)
        for v in obj.values(): res.extend(extract_dicts(v))
    elif isinstance(obj, list):
        for i in obj: res.extend(extract_dicts(i))
    return res

def generate_raw_link(n, name):
    from urllib.parse import quote
    encoded_name = quote(name)
    if n['type'] == 'hysteria2':
        # 修正断行隐患，使用单行拼接
        return f"hysteria2://{n['secret']}@{n['server']}:{n['port']}?sni={n['sni']}&insecure=1#{encoded_name}"
    elif n['type'] == 'vless':
        link = f"vless://{n['secret']}@{n['server']}:{n['port']}?encryption=none&security=tls&sni={n['sni']}"
        if n.get('pbk'):
            link = link.replace("security=tls", "security=reality") + f"&fp=chrome&pbk={n['pbk']}&sid={n['sid']}"
        return f"{link}#{encoded_name}"
    return None

# --- 3. 主程序 ---
def main():
    all_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    target_urls = FIXED_SOURCES.copy()
    if os.path.exists(MANUAL_FILE):
        try:
            with open(MANUAL_
