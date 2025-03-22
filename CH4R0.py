#!/usr/bin/env python3
import os
import sys
import re
import time
import json
import random
import requests
import argparse
import subprocess
import shutil
import concurrent.futures
from collections import defaultdict
from datetime import datetime
from colorama import Fore, Back, Style, init

init(autoreset=True)

def print_banner():
    banners = [
        f"""{Fore.RED}
 ██████╗██╗  ██╗██╗  ██╗██████╗ ██████╗ 
██╔════╝██║  ██║██║  ██║╚════██╗╚════██╗
██║     ███████║███████║ █████╔╝ █████╔╝
██║     ██╔══██║██╔══██║██╔═══╝ ██╔═══╝ 
╚██████╗██║  ██║██║  ██║███████╗███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
                                        
          [ M4D3 BY XYZ ]              
{Style.RESET_ALL}""",
        f"""{Fore.CYAN}
  ____ _  _ _   _ ___  ____  
 / ___| || | | | | _ \\|  _ \\ 
| |   | || |_| | | | | |_) |
| |___|__   _| |_| |  _ < 
 \\____|  |_|  \\___/|_| \\_\\
                            
      [ BY XYZ "charo ahbibi"]            
{Style.RESET_ALL}"""
    ]
    print(random.choice(banners))

class ToolManager:
    def __init__(self):
        self.tools = {
            "katana": {
                "cmd": "katana -u {} -silent -d 5 -kf all -jc -o {}",
                "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
                "description": "Advanced crawler"
            },
            "gospider": {
                "cmd": "gospider -s {} -d 3 -c 5 -t 100 -o {}",
                "install": "go install github.com/jaeles-project/gospider@latest",
                "description": "Web crawler"
            },
            "hakrawler": {
                "cmd": "echo {} | hakrawler -d 3 -u -insecure -h 'User-Agent: Mozilla/5.0' > {}",
                "install": "go install github.com/hakluke/hakrawler@latest",
                "description": "Recon crawler"
            },
            "httpx": {
                "cmd": "cat {} | httpx -silent -threads 100 -rate-limit 150 -timeout 5 -o {}",
                "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "description": "HTTP probe"
            },
            "nuclei": {
                "cmd": "nuclei -l {} -silent -c 50 -timeout 5 -retries 1 -severity low,medium,high,critical -o {}",
                "install": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
                "description": "Vuln scanner"
            },
            "gf": {
                "cmd": "gf {} -pattern {} -o {}",
                "install": "go install github.com/tomnomnom/gf@latest",
                "description": "Pattern tool"
            },
            "unfurl": {
                "cmd": "cat {} | unfurl -u domains > {}",
                "install": "go install github.com/tomnomnom/unfurl@latest",
                "description": "URL parser"
            }
        }
    
    def check_tools(self, required=None):
        if required is None:
            required = self.tools.keys()
        missing_tools = []
        for tool in required:
            if tool in self.tools and not shutil.which(tool):
                missing_tools.append((tool, self.tools[tool]["install"]))
        return missing_tools
    
    def install_command(self, tool):
        if tool in self.tools:
            return self.tools[tool]["install"]
        return None
    
    def get_command(self, tool, *args):
        if tool in self.tools:
            return self.tools[tool]["cmd"].format(*args)
        return None

class UrlHarvester:
    def __init__(self, output_dir, tool_manager):
        self.output_dir = output_dir
        self.tool_manager = tool_manager
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        ]
    
    def fetch_using_katana(self, target, target_dir):
        katana_file = f"{target_dir}/katana_urls.txt"
        clean_target = re.sub(r'^https?://', '', target)
        target_with_protocol = f"https://{clean_target}"
        try:
            cmd = self.tool_manager.get_command("katana", target_with_protocol, katana_file)
            subprocess.run(cmd, shell=True, stderr=subprocess.PIPE)
            if os.path.exists(katana_file) and os.path.getsize(katana_file) > 0:
                with open(katana_file, 'r') as f:
                    url_count = sum(1 for _ in f)
                print(Fore.GREEN + f"[+] Katana: {url_count} URLs" + Style.RESET_ALL)
                return katana_file
            else:
                return None
        except Exception as e:
            return None
    
    def fetch_using_gospider(self, target, target_dir):
        gospider_dir = f"{target_dir}/gospider_output"
        gospider_file = f"{target_dir}/gospider_urls.txt"
        clean_target = re.sub(r'^https?://', '', target)
        target_with_protocol = f"https://{clean_target}"
        try:
            os.makedirs(gospider_dir, exist_ok=True)
            cmd = self.tool_manager.get_command("gospider", target_with_protocol, gospider_dir)
            subprocess.run(cmd, shell=True, stderr=subprocess.PIPE)
            with open(gospider_file, 'w') as outfile:
                for file in os.listdir(gospider_dir):
                    if os.path.isfile(f"{gospider_dir}/{file}"):
                        with open(f"{gospider_dir}/{file}", 'r') as infile:
                            for line in infile:
                                if '[url]' in line:
                                    url = line.split('[url] ')[1].strip()
                                    outfile.write(f"{url}\n")
            if os.path.getsize(gospider_file) > 0:
                with open(gospider_file, 'r') as f:
                    url_count = sum(1 for _ in f)
                print(Fore.GREEN + f"[+] GoSpider: {url_count} URLs" + Style.RESET_ALL)
                return gospider_file
            else:
                return None
        except Exception as e:
            return None
    
    def fetch_using_hakrawler(self, target, target_dir):
        hakrawler_file = f"{target_dir}/hakrawler_urls.txt"
        clean_target = re.sub(r'^https?://', '', target)
        target_with_protocol = f"https://{clean_target}"
        try:
            cmd = self.tool_manager.get_command("hakrawler", target_with_protocol, hakrawler_file)
            subprocess.run(cmd, shell=True, stderr=subprocess.PIPE)
            if os.path.exists(hakrawler_file) and os.path.getsize(hakrawler_file) > 0:
                with open(hakrawler_file, 'r') as f:
                    url_count = sum(1 for _ in f)
                print(Fore.GREEN + f"[+] Hakrawler: {url_count} URLs" + Style.RESET_ALL)
                return hakrawler_file
            else:
                return None
        except Exception as e:
            return None
    
    def fetch_from_wayback(self, target, target_dir, use_filter=False):
        wayback_file = f"{target_dir}/wayback_urls.txt"
        file_extensions = r'.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc)$'
        clean_target = re.sub(r'^https?://', '', target)
        if clean_target.startswith('*.'):
            base_url = f"https://web.archive.org/cdx/search/cdx?url={clean_target}/*&collapse=urlkey&output=json&fl=original,timestamp,statuscode"
        else:
            base_url = f"https://web.archive.org/cdx/search/cdx?url=*.{clean_target}/*&collapse=urlkey&output=json&fl=original,timestamp,statuscode"
        if use_filter:
            url = f"{base_url}&filter=original:{file_extensions}"
        else:
            url = base_url
        headers = {'User-Agent': random.choice(self.user_agents)}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if not data or len(data) <= 1:
                return None
            unique_urls = set()
            url_data = []
            for item in data[1:]:
                url = item[0]
                timestamp = item[1]
                statuscode = item[2] if len(item) > 2 else "N/A"
                unique_urls.add(url)
                url_data.append({"url": url, "timestamp": timestamp, "statuscode": statuscode})
            with open(wayback_file, 'w') as f:
                for url in unique_urls:
                    f.write(f"{url}\n")
            with open(f"{target_dir}/wayback_details.json", 'w') as f:
                json.dump(url_data, f, indent=2)
            print(Fore.GREEN + f"[+] Wayback: {len(unique_urls)} URLs" + Style.RESET_ALL)
            return wayback_file
        except:
            return None

    def fetch_from_common_crawl(self, target, target_dir):
        cc_file = f"{target_dir}/commoncrawl_urls.txt"
        clean_target = re.sub(r'^https?://', '', target)
        clean_target = re.sub(r'^\*\.', '', clean_target)
        try:
            index_response = requests.get("https://index.commoncrawl.org/collinfo.json")
            latest_index = index_response.json()[0]["id"]
            cc_url = f"https://index.commoncrawl.org/{latest_index}-index?url=*.{clean_target}/*&output=json"
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = requests.get(cc_url, headers=headers)
            urls = set()
            for line in response.text.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if "url" in data:
                            urls.add(data["url"])
                    except:
                        continue
            with open(cc_file, 'w') as f:
                f.write('\n'.join(urls))
            print(Fore.GREEN + f"[+] CommonCrawl: {len(urls)} URLs" + Style.RESET_ALL)
            return cc_file if urls else None
        except:
            return None

    def combine_url_sources(self, url_files, target_dir):
        combined_file = f"{target_dir}/combined_urls.txt"
        all_urls = set()
        total_files = 0
        for file in url_files:
            if file and os.path.exists(file) and os.path.getsize(file) > 0:
                total_files += 1
                with open(file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            all_urls.add(url)
        if all_urls:
            with open(combined_file, 'w') as f:
                f.write('\n'.join(all_urls))
            print(Fore.GREEN + f"[+] Combined: {len(all_urls)} URLs" + Style.RESET_ALL)
            return combined_file
        else:
            return None

class UrlProcessor:
    def __init__(self, output_dir, tool_manager):
        self.output_dir = output_dir
        self.tool_manager = tool_manager
    
    def filter_urls_with_params(self, urls_file, target_dir):
        filtered_file = f"{target_dir}/filtered_urls.txt"
        try:
            with open(urls_file, 'r') as f:
                urls = f.read().splitlines()
            params_urls = [url for url in urls if re.search(r'\?[^=]+=.+$', url)]
            params_urls = list(set(params_urls))
            with open(filtered_file, 'w') as f:
                f.write('\n'.join(params_urls))
            print(Fore.GREEN + f"[+] Params: {len(params_urls)}" + Style.RESET_ALL)
            return filtered_file
        except:
            return urls_file
    
    def extract_js_files(self, urls_file, target_dir):
        js_file = f"{target_dir}/js_files.txt"
        try:
            with open(urls_file, 'r') as f:
                urls = f.read().splitlines()
            js_urls = [url for url in urls if re.search(r'\.js(\?|$)', url, re.IGNORECASE)]
            js_urls = list(set(js_urls))
            with open(js_file, 'w') as f:
                f.write('\n'.join(js_urls))
            print(Fore.GREEN + f"[+] JS Files: {len(js_urls)}" + Style.RESET_ALL)
            return js_file if js_urls else None
        except:
            return None
    
    def check_live_urls(self, urls_file, target_dir):
        live_urls_file = f"{target_dir}/live_urls.txt"
        try:
            cmd = self.tool_manager.get_command("httpx", urls_file, live_urls_file)
            subprocess.run(cmd, shell=True)
            if os.path.exists(live_urls_file) and os.path.getsize(live_urls_file) > 0:
                with open(live_urls_file, 'r') as f:
                    url_count = sum(1 for _ in f)
                print(Fore.GREEN + f"[+] Live: {url_count}" + Style.RESET_ALL)
                return live_urls_file
            else:
                return None
        except:
            return None
    
    def categorize_links(self, urls_file, target_dir):
        try:
            with open(urls_file, 'r') as f:
                links = f.read().splitlines()
            file_extensions = re.compile(r'.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc)$', re.IGNORECASE)
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            sensitive_pattern = re.compile(r'(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card|identity|id number|company confidential|staff only|management only|internal only|admin|password|credential|token|secret|key)', re.IGNORECASE)
            api_pattern = re.compile(r'(api|graphql|v1|v2|v3|rest|soap|backend|json|xml|swagger)/.*', re.IGNORECASE)
            file_leak_pattern = re.compile(r'(backup|dump|temp|old|copy|bak|temp|tmp|log|debug)', re.IGNORECASE)
            categorized = defaultdict(list)
            email_links = []
            sensitive_links = []
            api_links = []
            file_leak_links = []
            for link in links:
                if email_pattern.search(link):
                    email_links.append(link)
                if sensitive_pattern.search(link):
                                        sensitive_links.append(link)
                if api_pattern.search(link):
                    api_links.append(link)
                if file_leak_pattern.search(link):
                    file_leak_links.append(link)
                match = file_extensions.search(link)
                if match:
                    ext = match.group(1).lower()
                    categorized[ext].append(link)
            for ext, ext_links in categorized.items():
                filename = f"{target_dir}/category-{ext}.txt"
                with open(filename, "w") as file:
                    file.write("\n".join(ext_links))
                print(Fore.CYAN + f"[+] Category {ext}: {len(ext_links)}" + Style.RESET_ALL)
            if email_links:
                with open(f"{target_dir}/category-emails.txt", "w") as file:
                    file.write("\n".join(email_links))
                print(Fore.YELLOW + f"[+] Emails: {len(email_links)}" + Style.RESET_ALL)
            if sensitive_links:
                with open(f"{target_dir}/category-sensitive.txt", "w") as file:
                    file.write("\n".join(sensitive_links))
                print(Fore.RED + f"[+] Sensitive: {len(sensitive_links)}" + Style.RESET_ALL)
            if api_links:
                with open(f"{target_dir}/category-api.txt", "w") as file:
                    file.write("\n".join(api_links))
                print(Fore.MAGENTA + f"[+] API: {len(api_links)}" + Style.RESET_ALL)
            if file_leak_links:
                with open(f"{target_dir}/category-file-leaks.txt", "w") as file:
                    file.write("\n".join(file_leak_links))
                print(Fore.RED + f"[+] File Leaks: {len(file_leak_links)}" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[-] Categorization failed: {str(e)}" + Style.RESET_ALL)
            return False

class SecurityScanner:
    def __init__(self, output_dir, tool_manager):
        self.output_dir = output_dir
        self.tool_manager = tool_manager
    
    def run_nuclei_scan(self, urls_file, target_dir):
        nuclei_results = f"{target_dir}/nuclei_results.txt"
        try:
            cmd = self.tool_manager.get_command("nuclei", urls_file, nuclei_results)
            subprocess.run(cmd, shell=True)
            if os.path.exists(nuclei_results) and os.path.getsize(nuclei_results) > 0:
                with open(nuclei_results, 'r') as f:
                    vuln_count = sum(1 for _ in f)
                print(Fore.RED + f"[!] Nuclei: {vuln_count} findings" + Style.RESET_ALL)
                subprocess.run(f"head -n 5 {nuclei_results}", shell=True)
            else:
                print(Fore.YELLOW + "[+] Nuclei: No findings" + Style.RESET_ALL)
            return nuclei_results
        except Exception as e:
            print(Fore.RED + f"[-] Nuclei failed: {str(e)}" + Style.RESET_ALL)
            return None

def main():
    print_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    args = parser.parse_args()

    output_dir = args.output
    target = args.target
    target_dir = f"{output_dir}/{target}"

    os.makedirs(target_dir, exist_ok=True)

    tool_manager = ToolManager()
    missing_tools = tool_manager.check_tools()
    if missing_tools:
        print(Fore.RED + "[-] Missing tools detected:" + Style.RESET_ALL)
        for tool, install_cmd in missing_tools:
            print(Fore.YELLOW + f"[!] {tool}: {install_cmd}" + Style.RESET_ALL)
        sys.exit(1)

    harvester = UrlHarvester(output_dir, tool_manager)
    processor = UrlProcessor(output_dir, tool_manager)
    scanner = SecurityScanner(output_dir, tool_manager)

    print(Fore.CYAN + "\n[+] Starting URL harvesting..." + Style.RESET_ALL)
    katana_urls = harvester.fetch_using_katana(target, target_dir)
    gospider_urls = harvester.fetch_using_gospider(target, target_dir)
    hakrawler_urls = harvester.fetch_using_hakrawler(target, target_dir)
    wayback_urls = harvester.fetch_from_wayback(target, target_dir)
    commoncrawl_urls = harvester.fetch_from_common_crawl(target, target_dir)

    combined_urls = harvester.combine_url_sources(
        [katana_urls, gospider_urls, hakrawler_urls, wayback_urls, commoncrawl_urls],
        target_dir
    )

    if not combined_urls:
        print(Fore.RED + "[-] No URLs found. Exiting." + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.CYAN + "\n[+] Processing URLs..." + Style.RESET_ALL)
    filtered_urls = processor.filter_urls_with_params(combined_urls, target_dir)
    js_files = processor.extract_js_files(combined_urls, target_dir)
    live_urls = processor.check_live_urls(combined_urls, target_dir)
    processor.categorize_links(combined_urls, target_dir)

    print(Fore.CYAN + "\n[+] Running security scans..." + Style.RESET_ALL)
    scanner.run_nuclei_scan(combined_urls, target_dir)

    print(Fore.GREEN + "\n[+] CH4R0 scan completed!" + Style.RESET_ALL)

if __name__ == "__main__":
    main()