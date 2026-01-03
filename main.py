import json, urllib.request, yaml, os, ssl, warnings, re

warnings.filterwarnings("ignore")
OUT_DIR = './sub'
MANUAL_FILE = './urls/manual_json.txt'
os.makedirs(OUT_DIR, exist_ok=True)
ctx = ssl._create_unverified_context()

def get_geo(ip):
    """增加默认值，防止因为 API 请求失败导致整个节点丢失"""
    return "🌐" 

def handle_vless_reality(d):
    try:
        s, p, u = d.get('server') or d.get('add'), d.get('server_port') or d.get('port'), d.get('uuid') or d.get('id')
        if not (s and u): return None
        tls = d.get('tls', {})
        real = tls.get('reality', {}) if isinstance(tls, dict) else {}
        return {"s":str(s),"p":int(p),"u":str(u),"t":"vless","sn":tls.get('server_name') if isinstance(tls, dict) else d.get('sni','itunes.apple.com'),"pbk":real.get('public_key'),"sid":real.get('short_id')}
    except: return None

def handle_hy2_native(d):
    try:
        s_raw, u = str(d.get('server', '')), d.get('auth') or d.get('auth_str') or d.get('password')
        if not s_raw or not u: return None
        host = s_raw.split(':')[0].replace('[','').replace(']','')
        port = re.findall(r'\d+', s_raw.split(':')[1])[0] if ':' in s_raw else 443
        return {"s":host,"p":int(port),"u":str(u),"t":"hysteria2","sn":d.get('sni') or d.get('server_name') or "www.apple.com"}
    except: return None

def handle_naive(d):
    try:
        p_str = d.get('proxy', '')
        if 'https://' not in p_str: return None
        m = re.search(r'https://([^:]+):([^@]+)@([^:]+):(\d+)', p_str)
        if m: return {"u":m.group(1),"pass":m.group(2),"s":m.group(3),"p":int(m.group(4)),"t":"naive","sn":m.group(3)}
    except: return None

def handle_juicity(d):
    try:
        s, u, pw = d.get('server',''), d.get('uuid'), d.get('password')
        if not (s and u and pw): return None
        host, port = s.rsplit(':', 1)
        return {"s":host,"p":int(port),"u":str(u),"pw":str(pw),"t":"juicity","sn":d.get('sni',host),"cc":d.get('congestion_control','bbr')}
    except: return None

def find_dicts(obj):
    """深度递归提取所有字典，无论嵌套多深"""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values(): yield from find_dicts(v)
    elif isinstance(obj, list):
        for i in obj: yield from find_dicts(i)

def main():
    if not os.path.exists(MANUAL_FILE): 
        print(f"File not found: {MANUAL_FILE}")
        return
    
    with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
        urls = re.findall(r'https?://[^\s\'"\[\],]+', f.read())
    
    nodes = []
    print(f"Starting to fetch {len(urls)} URLs...")
    
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw_content = resp.read().decode('utf-8', errors='ignore')
                # 兼容 JSON 和 YAML
                try:
                    data = json.loads(raw_content)
                except:
                    data = yaml.safe_load(raw_content)
                
                # 全量协议提取：不再依赖 URL 路径，对每个字典尝试所有解析器
                count_before = len(nodes)
                for d in find_dicts(data):
                    n = handle_vless_reality(d) or handle_hy2_native(d) or handle_juicity(d) or handle_naive(d)
                    if n: nodes.append(n)
                print(f"Fetched {len(nodes) - count_before} nodes from {url}")
        except Exception as e:
            print(f"Error fetching {url}: {e}")

    # 去重
    uniq, seen, clash_px = [], set(), []
    for n in nodes:
        k = (n['s'], n['p'], n['u'])
        if k not in seen: uniq.append(n); seen.add(k)

    for i, n in enumerate(uniq):
        name = f"{get_geo(n['s'])} {n['t'].upper()}_{i+1}"
        px = {"name":name,"server":n['s'],"port":n['p'],"skip-cert-verify":True}
        if n['t'] == 'vless':
            px.update({"type":"vless","uuid":n['u'],"tls":True,"servername":n['sn'],"network":"tcp","udp":True})
            if n.get('pbk'): px.update({"reality-opts":{"public-key":n['pbk'],"short-id":n.get('sid','')}})
        elif n['t'] == 'hysteria2':
            px.update({"type":"hysteria2","password":n['u'],"sni":n['sn']})
        elif n['t'] == 'naive':
            px.update({"type":"http","username":n['u'],"password":n['pass'],"tls":True,"sni":n['sn'],"proxy-octet-stream":True})
        elif n['t'] == 'juicity':
            px.update({"type":"juicity","uuid":n['u'],"password":n['pw'],"sni":n['sn'],"congestion-control":n.get('cc','bbr')})
        clash_px.append(px)

    if not clash_px:
        print("⚠️ No nodes extracted. Please check if the source JSON matches the samples.")
        return

    conf = {"proxies":clash_px,"proxy-groups":[{"name":"🚀 自动选择","type":"url-test","proxies":[p['name'] for p in clash_px],"url":"http://www.gstatic.com/generate_204","interval":300},{"name":"🔰 手动切换","type":"select","proxies":["🚀 自动选择"]+[p['name'] for p in clash_px]}],"rules":["MATCH,🔰 手动切换"]}
    with open(f"{OUT_DIR}/clash.yaml", 'w', encoding='utf-8') as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
    print(f"✅ Success! Total nodes: {len(clash_px)}")

if __name__ == "__main__":
    main()
