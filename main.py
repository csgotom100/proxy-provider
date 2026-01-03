import json, urllib.request, yaml, os, ssl, warnings, re, base64

# ... (之前的 handle_vless, handle_hy2 等函数保持不变) ...

def main():
    # ... (之前的提取逻辑保持不变，直到生成 uniq 列表) ...
    
    # --- 新增：生成通用链接 (v2rayN) 逻辑 ---
    raw_links = []
    for n in uniq:
        try:
            if n['t'] == 'vless':
                link = f"vless://{n['u']}@{n['s']}:{n['p']}?encryption=none&security=reality&sni={n['sn']}&fp=chrome&pbk={n.get('pbk','')}&sid={n.get('sid','')}&type={n.get('net','tcp')}#VLESS_{n['s'][-5:]}"
                raw_links.append(link)
            elif n['t'] == 'hysteria2':
                link = f"hysteria2://{n['u']}@{n['s']}:{n['p']}?sni={n['sn']}&insecure=1#HY2_{n['s'][-5:]}"
                raw_links.append(link)
            elif n['t'] == 'juicity':
                link = f"juicity://{n['u']}:{n['pw']}@{n['s']}:{n['p']}?sni={n['sn']}#JUI_{n['s'][-5:]}"
                raw_links.append(link)
            # Naive 和 Mieru 通常没有标准通用分享链接，故略过或转为 SOCKS5
        except: continue

    # 1. 保存 Clash 格式 (保持原样)
    # ... (原有 Clash 生成代码) ...

    # 2. 保存 v2rayN 订阅格式 (Base64)
    v2_content = "\n".join(raw_links)
    v2_base64 = base64.b64encode(v2_content.encode('utf-8')).decode('utf-8')
    
    with open(f"{OUT_DIR}/v2rayn.txt", 'w', encoding='utf-8') as f:
        f.write(v2_base64)
    
    # 3. 保存直接可见的链接 (方便调试)
    with open(f"{OUT_DIR}/links.txt", 'w', encoding='utf-8') as f:
        f.write(v2_content)

    print(f"✅ Success! Clash nodes: {len(clash_px)}, v2rayN links: {len(raw_links)}")
