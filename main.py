import json, urllib.request, yaml, os, ssl, warnings, re, base64

warnings.filterwarnings("ignore")
BASE_DIR = os.getcwd()
OUT_DIR = os.path.join(BASE_DIR, 'sub')
MANUAL_FILE = os.path.join(BASE_DIR, 'urls', 'manual_json.txt')
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def parse_node(d):
    try:
        # --- 1. NaiveProxy (严格保持原始 https 字符串) ---
        if 'proxy' in d and str(d['proxy']).startswith('https://'):
            p_str = d['proxy']
            m = re.search(r'@([^:]+):(\d+)', p_str)
            if m:
                u_p = re.search(r'https://([^:]+):([^@]+)@', p_str).groups()
                return {"t": "naive", "raw": p_str, "s": m.group(1), "p": int(m.group(2)), "auth": u_p}

        # --- 2. Hysteria2 (按样本提取 TLS/SNI) ---
        if 'bandwidth' in d or 'quic' in d or str(d.get('type','')).lower() == 'hysteria2':
            s_raw = d.get('server', '')
            if not s_raw: return None
            s_part = str(s_raw).split(',')[0]
            host, port = s_part.split(':')[0].replace('[','').replace(']',''), s_part.split(':')[1] if ':' in s_part else 443
            u = d.get('auth') or d.get('password') or d.get('auth_str')
            tls = d.get('tls', {})
            return {"t": "hysteria2", "s": host, "p": int(port), "u": str(u), "sn": tls.get('sni'), "insecure": 1 if tls.get('insecure') else 0}

        # --- 3. VLESS (参数像素级同步) ---
        ptype = str(d.get('type') or d.get('protocol') or '').lower()
        if 'vless' in ptype:
            s, p, u = d.get('server') or d.get('add'), d.get('server_port') or d.get('port'), d.get('uuid') or d.get('id')
            if not (s and u): return None
            
            # 基础透传参数
            p_list = {
                "encryption": d.get("encryption", "none"),
                "flow": d.get("flow"),
                "packetEncoding": d.get("packet_encoding")
            }
            
            # 安全与传输层解析
            sec, sn, pbk, sid, fp, net = 'none', None, None, None, None, 'tcp'
            tls = d.get('tls', {})
            if tls and tls.get
