import json, urllib.request, yaml, os, ssl, warnings, re

# 1. 初始化环境
warnings.filterwarnings("ignore")
OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

# --- 🧪 协议实验室：精准解析器逻辑 ---

def handle_vless_reality(d):
    try:
        # 适配 Xray vnext 嵌套结构
        if 'vnext' in d.get('settings', {}):
            v = d['settings']['vnext'][0]
            s, p, u = v.get('address'), v.get('port'), v['users'][0].get('id')
        # 适配 Sing-box 平铺结构
        else:
            s, p, u = d.get('server') or d.get('add'), d.get('server_port') or d.get('port'), d.get('uuid') or d.get('id')
        
        if not (s and u): return None
        
        ss = d.get('streamSettings', {})
        real = ss.get('realitySettings', d.get('reality', {}))
        # 兼容 Xray (驼峰) 与 Sing-box (下划线) 命名的 Reality 参数
        sn = real.get('serverName') or ss.get('tlsSettings', {}).get('serverName') or d.get('sni', 'www.apple.com')
        pbk = real.get('publicKey') or d.get('public_key')
        sid = real.get('shortId') or d.get('short_id')
        
        return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","sn":sn,"pbk":pbk,"sid":sid,"net":ss.get('network','tcp')}
    except: return None

def handle_hy2_native(d):
    try:
        s_raw = str(d.get('server', ''))
        u = d.get('auth') or d.get('auth_str') or d.get('password')
        if not s_raw or not u or d.get('protocol') == 'freedom': return None
        host = s_raw.split(':')[0].replace('[','').replace(']','')
        port = re.findall(r'\d+', s_raw.split(':')[1])[0] if ':' in s_raw else 443
        return {"s":host,"p":int(port),"u":str(u),"t":"hysteria2","sn":d.get('sni') or d.get('server_name') or "www.apple.com"}
    except: return None

def handle_naive(d):
    try:
        p_str = d.get('proxy', '')
        if 'https://' not in str(p_str): return None
        m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', p_str)
        if m: return {"u":m.group(1),"pass":m.group(2),"s":m.group(3),"p":int(m.group(4)),"t":"naive","sn":m.group(3)}
    except: return None

def handle_
