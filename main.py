import json, urllib.request, yaml, os, ssl, warnings, re, time
from datetime import datetime, timedelta, timezone

# 忽略 SSL 证书校验警告
warnings.filterwarnings("ignore")

OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    """获取 IP 地理位置国旗标识"""
    try:
        clean_ip = ip.replace('[','').replace(']','')
        if not re.match(r'^\d', clean_ip) and not ':' in clean_ip: return "🏳️"
        url = f"http://ip-api.com/json/{clean_ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            code = json.loads(r.read().decode()).get('countryCode', 'UN')
            return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🏳️"

# --- 🧪 协议实验室：针对样板精准解析器 ---

def handle_vless_reality(d):
    """适配 VLESS Sing-box (Reality) 样板"""
    try:
        s = d.get('server') or d.get('add')
        p = d.get('server_port') or d.get('port')
        u = d.get('uuid') or d.get('id')
        if not (s and u): return None
        tls = d.get('tls', {})
        real = tls.get('reality', {}) if isinstance(tls, dict) else {}
        return {
            "s": str(s), "p": int(p), "u": str(u), "t": "vless",
            "sn": tls.get('server_name') if isinstance(tls, dict) else d.get('sni', ''),
            "pbk": real.get('public_key'), "sid": real.get('short_id')
        }
    except: return None

def handle_hy2_native(d):
    """适配 HY2 Native (处理端口跳跃格式及不同 auth 字段)"""
    try:
        s_raw = str(d.get('server', ''))
        # 兼容 auth, auth_str, password 字段
        u = d.get('auth') or d.get('auth_str') or d.get('password')
        if not s_raw or not u: return None
        
        # 处理 IP:Port1,Port2... 格式，仅提取首个主端口
        host = s_raw.split(':')[0].replace('[','').replace(']','')
        port_match = re.findall(r'\d+', s_raw.split(':')[1]) if ':' in s_raw else ['443']
        port = port_match[0]
        
        tls = d.get('tls', {})
        sn = d.get('sni') or d.get('server_name')
        if isinstance(tls, dict):
            sn = tls.get('sni') or tls.get('server_name') or sn
        return {"s": host, "p": int(port), "u": str(u), "t": "hysteria2", "sn": sn or "www.apple.com"}
    except: return None

def handle_naive(d):
    """适配 NaiveProxy 样板 (解析 https 代理字符串)"""
    proxy_str = d.get('proxy', '')
    if not proxy_str.startswith('https://'): return None
    try:
        # 匹配格式: https://user:pass@host:port
        m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', proxy_str)
        if m: 
            return {
                "u": m.group(1), "pass": m.group(2), "s": m.group(3), 
                "p": int(m.group(4)), "t": "naive", "sn": m.group(3)
            }
    except: return None

def handle_juicity(d):
    """适配 Juicity 样板 (UUID + Password)"""
    try:
        s_raw = d.get('server', '')
        u = d.get('uuid')
        pw = d.get('password')
        if
