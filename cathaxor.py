#!/usr/bin/env python3
import requests
from colorama import init, Fore, Style
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
import readline
import subprocess
import sys

init(autoreset=True)

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
WORDLIST_FILE = "burp-parameter-names.txt"

def banner():
    print(Fore.MAGENTA + Style.BRIGHT + """
   █▀▀ ▄▀█ ▀█▀ █░█ ▄▀█ ▀▄▀ █▀█ █▀█
   █▄▄ █▀█ ░█░ █▀█ █▀█ █░█ █▄█ █▀▄
""")
    print(Fore.YELLOW + Style.BRIGHT + "        OWNER: ABDULLA RAHAMAN\n")
    print(Fore.CYAN + Style.BRIGHT + "     >>>>>  C A T H A X O R  <<<<<\n")

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url.rstrip("/")

def is_numeric_param(param):
    return re.fullmatch(r"\d+", param) is not None

def test_url(url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return url
    except:
        return None
    return None

def download_wordlist():
    if not os.path.exists(WORDLIST_FILE):
        print(Fore.YELLOW + "[*] Downloading wordlist from SecLists...")
        try:
            r = requests.get(WORDLIST_URL, timeout=10)
            with open(WORDLIST_FILE, "w") as f:
                f.write(r.text)
            print(Fore.GREEN + "[+] Wordlist downloaded successfully!")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to download wordlist: {e}")
            exit(1)
    else:
        print(Fore.GREEN + f"[+] Wordlist already exists: {WORDLIST_FILE}")

def load_wordlist():
    with open(WORDLIST_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def setup_tab_completion(params):
    def completer(text, state):
        options = [p for p in params if p.startswith(text)]
        if state < len(options):
            return options[state]
        else:
            return None
    readline.parse_and_bind("tab: complete")
    readline.set_completer(completer)

def update_tool():
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    print(Fore.YELLOW + "[*] Checking for updates from GitHub...")
    try:
        result = subprocess.run(["git", "pull"], cwd=repo_dir, capture_output=True, text=True)
        print(result.stdout)
        if "Already up to date." in result.stdout:
            print(Fore.GREEN + "[+] CATHAXOR is already up to date.")
        else:
            print(Fore.GREEN + "[+] Update completed successfully.")
    except Exception as e:
        print(Fore.RED + f"[!] Update failed: {e}")
    sys.exit()

def main():
    banner()
    download_wordlist()
    params = load_wordlist()
    numeric_params = [param for param in params if is_numeric_param(param)]

    print(Fore.GREEN + f"[+] Loaded {len(numeric_params)} numeric parameters\n")

    setup_tab_completion(numeric_params)

    target = input(Fore.YELLOW + "Enter target website URL: ").strip()
    url_base = normalize_url(target)
    print(Fore.GREEN + f"[*] Connecting to: {url_base}\n")
    print(Fore.GREEN + "[+] Scanning for numeric parameterized URLs...\n")

    urls_to_test = [f"{url_base}?{param}" for param in numeric_params]
    found = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_url, url): url for url in urls_to_test}
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(Fore.GREEN + f"[+] {result}")
                found.append(result)

    print(Fore.MAGENTA + "\n[CATHAXOR] Scan complete.\n")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "--update":
        update_tool()
    else:
        main()
