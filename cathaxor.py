#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import os
import re
import sys
import subprocess

init(autoreset=True)

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
WORDLIST_FILE = "burp-parameter-names.txt"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}


# Display Banner
def banner():
    print(Fore.MAGENTA + Style.BRIGHT + """
   █▀▀ ■▀▀ ■▀▀ ▀△ ▀▀ ■▀▀ ■▀▀
   ▀▄ ▀▄ ▪ ■▄ ▀▄ ▪ ▄■▄▀▀
""")
    print(Fore.YELLOW + Style.BRIGHT + "        CATHAXOR - PARAMETER FINDER TOOL")
    print(Fore.CYAN + Style.BRIGHT + "             OWNER: ABDULLA RAHAMAN\n")


def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        return ['http://' + url, 'https://' + url]
    return [url]


def is_numeric_param(param):
    return re.fullmatch(r"\d+", param) is not None


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
        return [line.strip() for line in f if line.strip() and is_numeric_param(line.strip())]


def find_pages(base_url):
    visited = set()
    found_pages = set()
    try:
        res = requests.get(base_url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if base_url in full_url and (".php" in parsed.path or ".asp" in parsed.path or ".html" in parsed.path):
                found_pages.add(full_url)
    except:
        pass
    return list(found_pages)


def test_param_url(url, param):
    full_url = f"{url}?id={param}"
    try:
        r = requests.get(full_url, headers=HEADERS, timeout=5)
        if r.status_code == 200:
            return full_url
    except:
        return None
    return None


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
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        update_tool()

    banner()
    download_wordlist()
    params = load_wordlist()

    target = input(Fore.YELLOW + "Enter target website URL: ").strip()
    targets = normalize_url(target)

    for base_url in targets:
        print(Fore.GREEN + f"[*] Connecting to: {base_url}")
        pages = find_pages(base_url)
        print(Fore.CYAN + f"[+] Found {len(pages)} pages to test\n")

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = []
            for page in pages:
                for param in params:
                    futures.append(executor.submit(test_param_url, page, param))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(Fore.GREEN + f"[+] {result}")

    print(Fore.MAGENTA + "\n[CATHAXOR] Scan complete.\n")


if __name__ == "__main__":
    main()
