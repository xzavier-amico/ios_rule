#!/usr/bin/env python3
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    
    def fetch_and_process_rule(self, target_url):
        try:
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0 DelegateService/2.0'})
            with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
                content = response.read().decode('utf-8')

            lines = content.split('\n')
            new_lines = []
            
            for line in lines:
                cleaned_line = line.rstrip('\r')
                
                # 【核心新增】Loon 兼容逻辑：将 Clash 格式的 IPv6 转换为 IP-CIDR6
                if cleaned_line.startswith('IP-CIDR,') and ':' in cleaned_line:
                    cleaned_line = cleaned_line.replace('IP-CIDR,', 'IP-CIDR6,', 1)

                # 追加 no-resolve
                if cleaned_line.startswith(('IP-CIDR', 'IP-CIDR6', 'IP-ASN')):
                    if 'no-resolve' not in cleaned_line.lower():
                        cleaned_line += ',no-resolve'
                        
                new_lines.append(cleaned_line)

            return new_lines

        except urllib.error.HTTPError as e:
            print(f"[-] Skip {target_url} - HTTP {e.code}")
            return None
        except Exception as e:
            print(f"[-] Error fetching {target_url} - {str(e)}")
            return None

    def do_GET(self):
        parsed_url = urlparse(self.path)
        if parsed_url.path.startswith("/rule/"):
            self.handle_aggregated_rules(parsed_url)
        else:
            self.handle_legacy_proxy()

    def handle_legacy_proxy(self):
        target_url = self.path[1:]

        if target_url.startswith("https:/") and not target_url.startswith("https://"):
            target_url = target_url.replace("https:/", "https://", 1)
        elif target_url.startswith("http:/") and not target_url.startswith("http://"):
            target_url = target_url.replace("http:/", "http://", 1)

        if not target_url.startswith("http"):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid Format. Usage: /https://raw.githubusercontent.com/...")
            return

        result = self.fetch_and_process_rule(target_url)
        
        if result is not None:
            final_text = '\n'.join(result)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(final_text.encode('utf-8'))
        else:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Bad Gateway: Failed to fetch the requested rule.")

    def handle_aggregated_rules(self, parsed_url):
        path_parts = parsed_url.path.split('/')
        if len(path_parts) < 3:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid API path. Expected /rule/{type}")
            return

        rule_type = path_parts[2]
        query = parse_qs(parsed_url.query)
        categories_str = query.get('cate', [''])[0]
        
        if not categories_str:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing 'cate' parameter. Example: ?cate=private|cn")
            return
            
        categories = [c.strip() for c in categories_str.split('|') if c.strip()]
        combined_output = []
        seen_rules = set() 

        if rule_type == 'meta':
            base_geoip_url = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/classical/{}.list"
            base_geosite_url = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/classical/{}.list"
            
            for cat in categories:
                # ====== 处理 GeoIP ======
                geoip_url = base_geoip_url.format(cat)
                geoip_lines = self.fetch_and_process_rule(geoip_url)
                if geoip_lines:
                    combined_output.append(f"# ===== Meta GeoIP: {cat} =====")
                    for line in geoip_lines:
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue
                        if line_stripped.startswith('#'):
                            combined_output.append(line)
                        elif line not in seen_rules:
                            seen_rules.add(line)
                            combined_output.append(line)
                    print(f"[+] Successfully fetched GeoIP: {cat}")
                
                # ====== 处理 Geosite ======
                geosite_url = base_geosite_url.format(cat)
                geosite_lines = self.fetch_and_process_rule(geosite_url)
                if geosite_lines:
                    combined_output.append(f"# ===== Meta Geosite: {cat} =====")
                    for line in geosite_lines:
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue
                        if line_stripped.startswith('#'):
                            combined_output.append(line)
                        elif line not in seen_rules:
                            seen_rules.add(line)
                            combined_output.append(line)
                    print(f"[+] Successfully fetched Geosite: {cat}")

        elif rule_type == 'mine':
            base_geosite_url = "https://raw.githubusercontent.com/xzavier-amico/ios_rule/refs/heads/main/{}.list"
            
            for cat in categories:
                # ====== 处理 Geosite ======
                geosite_url = base_geosite_url.format(cat)
                geosite_lines = self.fetch_and_process_rule(geosite_url)
                if geosite_lines:
                    combined_output.append(f"# ===== Meta Geosite: {cat} =====")
                    for line in geosite_lines:
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue
                        if line_stripped.startswith('#'):
                            combined_output.append(line)
                        elif line not in seen_rules:
                            seen_rules.add(line)
                            combined_output.append(line)
                    print(f"[+] Successfully fetched Geosite: {cat}")

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(f"Unsupported rule type: {rule_type}".encode('utf-8'))
            return

        if combined_output:
            final_text = '\n'.join(combined_output) + '\n'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(final_text.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"No data found for the provided categories.")

if __name__ == '__main__':
    server_address = ('127.0.0.1', 10005)
    httpd = HTTPServer(server_address, ProxyHTTPRequestHandler)
    print("Rule Delegate Service is running on 127.0.0.1:10005...")
    httpd.serve_forever()