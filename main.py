import json
import urllib.request
import base64
import yaml
import os
import ssl
import warnings
import re
import time

warnings.filterwarnings("ignore")

# --- 配置 ---
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

def get_node_info(item):
    """极致宽容解析：只要有IP、端口、密钥就是好节点"""
    try:
        if not isinstance(item, dict): return None
        # 1. 找服务器
        srv = item.get('server') or item.get('add') or item.get('address') or item.get('host')
        if not srv or str(srv).startswith('127.'): return None
        
        # 2. 找端口
        port = item.get('port') or item.get('server_port') or item.get('port_num')
        if not port and ':' in str(srv):
            srv, port = str(srv).rsplit(':', 1)
        
        # 3. 找密钥
        pwd = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
        if not srv or not port or not pwd: return None

        # 清洗数据
        srv = str(srv).replace('[','').replace(']','')
        port = int(str(port).split(',')[0].split('-')[0].strip())
        
        # 协议识别
        t = str(item.get('type', '')).lower()
        if 'hy2' in t or 'hysteria2' in t or 'auth' in item: ntype = 'hysteria2'
        elif 'vless' in t or 'uuid' in item: ntype = 'vless'
        elif 'vmess' in t: ntype = 'vmess'
        elif 'ss' in t or 'shadowsocks' in t: ntype = 'ss'
        else: ntype = 'vless'

        # 特色参数提取
        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = item.get('sni') or item.get('servername') or tls_obj.get('server_name') or ""
        
        node = {"server": srv, "port": port, "type": ntype, "secret": str(pwd), "sni": sni}
        
        # Reality 处理
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

def main():
    all_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    
    # 合并订阅源
    target_urls = FIXED_SOURCES.copy()
    if os.path.exists(MANUAL_FILE):
        with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
            target_urls.extend(re.findall(r'https?://[^\s\'"\[\],]+', f.read()))
    
    target_urls = list(set(target_urls))
    print(f"📡 正在扫描 {len(target_urls)} 个源...")

    for url in target_urls:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw_text = resp.read().decode('utf-8', errors='ignore')
                count_before = len(all_nodes)
                
                # 尝试结构化解析
                try:
                    data = json.loads(raw_text) if raw_text.startswith(('{','[')) else yaml.safe_load(raw_text)
                    for d in extract_dicts(data):
                        node = get_node_info(d)
                        if node: all_nodes.append(node)
                except: pass
                
                # 尝试 Base64 暴力解码及正则提取 (兜底)
                if len(all_nodes) == count_before:
                    try:
                        decoded = base64.b64decode(raw_text).decode('utf-8', errors='ignore')
                        # 这里简单识别 vless:// 链接中的关键信息并模拟成字典
                        links
