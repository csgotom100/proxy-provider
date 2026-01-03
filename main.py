import json, urllib.request, yaml, os, ssl, warnings, re, base64, time
from datetime import datetime, timedelta, timezone

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
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ip/singbox/2/config.json"
]

OUT_DIR = './sub'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

# --- 2. 功能函数 ---
def get_geo_info(ip):
    """获取地理位置并转换成国旗"""
    try:
        # 简单过滤 IPv6 括号
        clean_ip = ip.replace('[','').replace(']','')
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode())
            if data.get('status') == 'success':
                code = data.get('countryCode', 'UN')
                # 国家代码转国旗 Emoji
                return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: pass
    return "🏳️"

def get_node(item):
    """解析节点信息"""
    try:
        if not isinstance(item, dict): return None
        s = item.get('server') or item.get('add') or item.get('address')
        p = item.get('port') or item.get('server_port') or item.get('port_num')
        u = item.get('password') or item.get('uuid') or item.get('id') or item.get('auth')
        if not s or not p or not u: return None
        
        s = str(s).replace('[','').replace(']','')
        p =
