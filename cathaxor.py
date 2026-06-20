#!/usr/bin/env python3
import os
import sys
import subprocess

def install_requirements():
    try:
        import requests
        import bs4
        import colorama
        import urllib3
    except ImportError:
        print("[*] Missing required modules. Installing them automatically...")
        req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
        try:
            if os.path.exists(req_file):
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
            else:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "beautifulsoup4", "colorama", "urllib3"])
            print("[+] Installation complete. Please restart the tool.")
        except Exception as e:
            print(f"[!] Failed to install requirements: {e}")
            print("Please run manually: pip install -r requirements.txt")
        sys.exit(1)

install_requirements()

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import argparse
import urllib3
import random
import time
import threading

# Disable SSL Warnings for poorly configured targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

stop_event = threading.Event()

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"

# A highly effective, hand-picked list of top ~110 parameters for fast fuzzing
SMALL_PARAMS = [
    "id", "user", "dir", "file", "path", "folder", "doc", "page", "api", "cmd", 
    "exec", "command", "url", "uri", "link", "src", "target", "dest", "redirect",
    "next", "view", "show", "debug", "test", "edit", "update", "delete", "remove",
    "query", "q", "search", "keyword", "filter", "sort", "order", "limit", "offset",
    "page_no", "lang", "locale", "theme", "style", "template", "layout", "config",
    "cfg", "setup", "admin", "role", "level", "group", "type", "mode", "action",
    "do", "func", "method", "class", "obj", "object", "item", "article", "post",
    "comment", "msg", "message", "txt", "text", "str", "string", "data", "input",
    "out", "output", "format", "ext", "extension", "download", "upload", "file_name",
    "filename", "img", "image", "pic", "picture", "photo", "avatar", "profile",
    "email", "mail", "pass", "password", "pwd", "token", "auth", "key", "secret",
    "hash", "sig", "signature", "nonce", "state", "code", "ver", "version", "rev",
    "callback", "cb", "jsonp", "ref", "referer", "referrer", "site", "domain",
    "host", "ip", "port", "mac", "net", "network", "subnet", "gateway", "dns",
    "session", "uuid", "guid", "pid", "uid", "sid", "tid", "cid", "qid"
]

# Modern User-Agents for rotation to bypass basic WAFs
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

def banner():
    print(Fore.MAGENTA + Style.BRIGHT + """
░█▀▀█ ─█▀▀█ ▀▀█▀▀ ░█─░█ ─█▀▀█ ▀▄░▄▀ ░█▀▀▀█ ░█▀▀█ 
░█─── ░█▄▄█ ─░█── ░█▀▀█ ░█▄▄█ ─░█── ░█──░█ ░█▄▄▀ 
░█▄▄█ ░█─░█ ─░█── ░█─░█ ░█─░█ ▄▀░▀▄ ░█▄▄▄█ ░█─░█
""")
    print(Fore.YELLOW + Style.BRIGHT + "    [ ADVANCED PARAMETER DISCOVERY TOOL ]")
    print(Fore.CYAN + Style.BRIGHT + "         OWNER: ABDULLA RAHAMAN\n")

def get_session(retries=3, backoff_factor=0.3, pool_maxsize=100):
    """Create a robust request session with retries to handle unstable networks"""
    session = requests.Session()
    retry = urllib3.util.Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(500, 502, 504),
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry, pool_connections=pool_maxsize, pool_maxsize=pool_maxsize)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        # Default to https, fallback to http is possible but https is standard now
        return 'https://' + url
    return url

def download_wordlist(wordlist_path):
    if not os.path.exists(wordlist_path):
        print(Fore.YELLOW + f"[*] Downloading wordlist to {wordlist_path}...")
        try:
            r = requests.get(WORDLIST_URL, timeout=10)
            with open(wordlist_path, "w", encoding='utf-8') as f:
                f.write(r.text)
            print(Fore.GREEN + "[+] Wordlist downloaded successfully!")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to download wordlist: {e}")
            sys.exit(1)

def load_wordlist(wordlist_path):
    with open(wordlist_path, "r", encoding='utf-8') as f:
        return list(set([line.strip() for line in f if line.strip()]))

def find_pages(session, base_url, headers, cookies, crawl_enabled=False):
    found_pages = set()
    found_pages.add(base_url)
    
    if not crawl_enabled:
        return list(found_pages)
        
    try:
        res = session.get(base_url, headers=headers, cookies=cookies, timeout=5, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link.get('href')
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:')):
                continue
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if urlparse(base_url).netloc == parsed.netloc:
                if parsed.path.endswith((".php", ".asp", ".aspx", ".jsp", ".html", "/")) or "." not in parsed.path.split("/")[-1]:
                    clean_url = full_url.split("?")[0].split("#")[0]
                    found_pages.add(clean_url)
    except Exception as e:
        print(Fore.RED + f"[!] Error crawling {base_url}: {e}")
    return list(found_pages)

def evaluate_dynamic_content(session, url, headers, cookies):
    """
    Makes multiple requests to the same URL to determine the variance in response length.
    This helps prevent false positives on dynamic pages (like ad rotation, time counters, CSRF tokens).
    """
    lengths = []
    status_codes = set()
    try:
        for _ in range(2):
            headers["User-Agent"] = random.choice(USER_AGENTS)
            r = session.get(url, headers=headers, cookies=cookies, timeout=5, verify=False)
            lengths.append(len(r.text))
            status_codes.add(r.status_code)
            time.sleep(0.3)
            
        min_len = min(lengths)
        max_len = max(lengths)
        variance = max_len - min_len
        # Check if server blindly reflects URL parameters
        dummy_val = f"cathaxordummy{random.randint(1000,9999)}"
        dummy_url = f"{url}?cathaxordummy={dummy_val}"
        r_dummy = session.get(dummy_url, headers=headers, cookies=cookies, timeout=5, verify=False)
        reflects_url = dummy_val in r_dummy.text

        return {
            "min_length": min_len,
            "max_length": max_len,
            "variance": variance,
            "status": list(status_codes)[0] if len(status_codes) == 1 else None,
            "is_stable": variance < 50,
            "reflects_url": reflects_url
        }
    except:
        return None

def test_param_url(session, url, param, base_info, headers, cookies, delay):
    if stop_event.is_set():
        return None
    if delay:
        time.sleep(delay)
        
    test_value = f"cathaxor{random.randint(1000,9999)}"
    full_url = f"{url}?{param}={test_value}"
    headers["User-Agent"] = random.choice(USER_AGENTS)
    
    try:
        r = session.get(full_url, headers=headers, cookies=cookies, timeout=5, verify=False)
        
        # Heuristic 1: Reflection Detection
        if not base_info["reflects_url"] and test_value in r.text:
            return (full_url, "Value Reflected in Response")
            
        # Heuristic 2: Status Code Change
        if base_info["status"] and r.status_code != base_info["status"] and r.status_code not in [404, 403, 400]:
            return (full_url, f"Status Anomaly (Base: {base_info['status']} -> New: {r.status_code})")
            
        # Heuristic 3: Significant Length Change based on variance
        current_len = len(r.text)
        tolerance = max(50, base_info["variance"] * 2)
        
        if current_len > (base_info["max_length"] + tolerance) or current_len < (base_info["min_length"] - tolerance):
            return (full_url, f"Length Changed: {current_len} (Base Range: {base_info['min_length']}-{base_info['max_length']})")
            
    except:
        pass
    return None

def update_tool():
    print(Fore.YELLOW + "[*] Checking for updates from GitHub...")
    url = "https://raw.githubusercontent.com/cathaxor/param-finder/main/cathaxor.py"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            current_script = os.path.abspath(__file__)
            with open(current_script, 'r', encoding='utf-8') as f:
                current_code = f.read()
            if current_code == response.text:
                print(Fore.GREEN + "[+] CATHAXOR is already up to date.")
            else:
                with open(current_script, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                print(Fore.GREEN + "[+] Update completed successfully. Please run the tool again.")
        else:
            print(Fore.RED + f"[!] Update failed. GitHub returned status: {response.status_code}")
    except PermissionError:
        print(Fore.RED + "[!] Permission denied. Try running with 'sudo python cathaxor.py --update' (Linux) or Run as Administrator (Windows).")
    except Exception as e:
        print(Fore.RED + f"[!] Update failed: {e}")
    sys.exit()

def parse_headers(header_list):
    headers = {}
    if header_list:
        for h in header_list:
            if ':' in h:
                key, val = h.split(':', 1)
                headers[key.strip()] = val.strip()
    return headers

def parse_cookies(cookie_string):
    cookies = {}
    if cookie_string:
        for c in cookie_string.split(';'):
            if '=' in c:
                key, val = c.split('=', 1)
                cookies[key.strip()] = val.strip()
    return cookies

def main():
    parser = argparse.ArgumentParser(description="CatHaxor - Advanced Web Parameter Discovery Tool")
    parser.add_argument("-u", "--url", help="Target URL (e.g. http://example.com)")
    parser.add_argument("-w", "--wordlist", help="Wordlist to use: 'small' (built-in ~110 params), 'big' (SecLists 6400 params), or custom file path. (Default: small)", default="small")
    parser.add_argument("-t", "--threads", help="Number of threads (Default: 30)", type=int, default=30)
    parser.add_argument("-o", "--output", help="Save output to file")
    parser.add_argument("-d", "--delay", help="Delay between requests in seconds (Default: 0)", type=float, default=0)
    parser.add_argument("-H", "--header", help="Custom Header (e.g. -H 'Authorization: Bearer token')", action='append')
    parser.add_argument("-c", "--cookies", help="Custom Cookies (e.g. 'session=123; user=admin')")
    parser.add_argument("--crawl", action="store_true", help="Crawl the target URL to find other pages and test all of them")
    parser.add_argument("--update", action="store_true", help="Update the tool from GitHub")
    
    banner()
    args = parser.parse_args()

    if args.update:
        update_tool()

    if not args.url:
        print(Fore.RED + "[!] Please provide a target URL using -u or --url")
        print(Fore.YELLOW + "Usage example: python cathaxor.py -u http://example.com\n")
        parser.print_help()
        sys.exit(1)

    target_url = normalize_url(args.url)
    custom_headers = parse_headers(args.header)
    custom_cookies = parse_cookies(args.cookies)
    
    if args.wordlist.lower() == "small":
        params = SMALL_PARAMS
        print(Fore.GREEN + f"[+] Loaded {len(params)} high-impact parameters (Fast Mode).")
    elif args.wordlist.lower() == "big":
        wordlist_file = "burp-parameter-names.txt"
        download_wordlist(wordlist_file)
        print(Fore.YELLOW + f"[*] Loading wordlist: {wordlist_file}")
        params = load_wordlist(wordlist_file)
        print(Fore.GREEN + f"[+] Loaded {len(params)} parameters.")
    else:
        if not os.path.exists(args.wordlist):
            print(Fore.RED + f"[!] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        print(Fore.YELLOW + f"[*] Loading custom wordlist: {args.wordlist}")
        params = load_wordlist(args.wordlist)
        print(Fore.GREEN + f"[+] Loaded {len(params)} parameters.")

    session = get_session(pool_maxsize=max(100, args.threads * 2))
    
    if args.crawl:
        print(Fore.YELLOW + f"[*] Crawling target: {target_url}")
    else:
        print(Fore.YELLOW + f"[*] Target URL: {target_url} (use --crawl to test all links)")
        
    pages = find_pages(session, target_url, custom_headers, custom_cookies, args.crawl)
    print(Fore.CYAN + f"[+] Found {len(pages)} pages to test\n")

    found_params = []
    lock = threading.Lock()

    try:
        for page in pages:
            if stop_event.is_set():
                break
            print(Fore.YELLOW + f"[*] Evaluating dynamic content for baseline on: {page}")
            base_info = evaluate_dynamic_content(session, page, custom_headers, custom_cookies)
            
            if not base_info:
                print(Fore.RED + f"[!] Failed to establish baseline for {page}. Skipping.")
                continue
                
            print(Fore.CYAN + f"[+] Baseline established. Stable: {base_info['is_stable']} | Variance: {base_info['variance']} bytes")
            print(Fore.YELLOW + f"[*] Starting parameter fuzzing on {page}...")
            
            tested = 0
            total = len(params)
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for param in params:
                    if stop_event.is_set():
                        break
                    futures.append(executor.submit(test_param_url, session, page, param, base_info, custom_headers.copy(), custom_cookies, args.delay))

                for future in as_completed(futures):
                    if stop_event.is_set():
                        break
                    tested += 1
                    sys.stdout.write(f"\r[*] Progress: {tested}/{total} parameters tested...")
                    sys.stdout.flush()
                    
                    result = future.result()
                    if result:
                        found_url, reason = result
                        with lock:
                            sys.stdout.write("\r" + " " * 60 + "\r")
                            print(Fore.GREEN + f"[+] VULNERABLE/ACTIVE PARAMETER FOUND: {found_url}")
                            print(Fore.GREEN + f" └── Reason: {reason}")
                            found_params.append(f"{found_url} -> [{reason}]")
            print()
    except KeyboardInterrupt:
        stop_event.set()
        print(Fore.RED + "\n[!] Scan interrupted by user (Ctrl+C). Stopping threads...")
    finally:
        if found_params:
            output_file = args.output
            if not output_file:
                domain = urlparse(target_url).netloc.replace(":", "_")
                output_file = f"cathaxor_{domain}.txt"
                
            with open(output_file, "w") as f:
                for p in found_params:
                    f.write(p + "\n")
            print(Fore.CYAN + f"\n[+] Results successfully saved to {output_file}")

        print(Fore.MAGENTA + "\n[CATHAXOR] Scan complete. Happy Hacking!\n")

if __name__ == "__main__":
    main()
