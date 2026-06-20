# CatHaxor - Advanced Parameter Discovery Tool

CatHaxor is a professional, multi-threaded Web Parameter Finder and Vulnerability Fuzzer. It uses advanced heuristics to discover active hidden parameters on web applications, effectively bypassing WAFs and evading false positives on dynamic pages.

## Features
- **Dynamic Content Evaluation**: Automatically detects if a web page is dynamically changing (time tokens, ads, CSRF tokens) to eliminate false positives.
- **Smart Heuristics**: Detects active parameters based on **Reflection**, **Status Code anomalies**, and **Length variances**.
- **WAF Evasion**: Automatically rotates modern User-Agents to prevent basic blocking.
- **Robust Network Engine**: Automatically retries failed connections using backoff algorithms.
- **Custom Authentication**: Supports custom HTTP headers and Cookies (`-H` and `-c`) to scan authenticated endpoints.
- **Auto Installer**: Automatically installs required dependencies if not found on the user's PC.
- **Auto Updater**: Keep the tool up-to-date directly from GitHub without needing git via `--update`.

## Requirements
The tool will automatically install its dependencies when run for the first time. However, if you want to install them manually:
```bash
pip install -r requirements.txt
```

## Global Installation (Linux)
You can install CatHaxor globally so you can run it from anywhere in your terminal just by typing `cathaxor`:

```bash
chmod +x cathaxor.py
sudo cp cathaxor.py /usr/local/bin/cathaxor
```

## Usage

**Basic Scan (Automatic wordlist download & scan)**
```bash
python cathaxor.py -u http://example.com
```

**Advanced Scan (50 Threads, Delay 0.2s, Custom Headers, Custom Cookies, Save to File)**
```bash
python cathaxor.py -u http://example.com/api/user -t 50 -d 0.2 -H "Authorization: Bearer token123" -c "session=abcdef;" -o found_params.txt
```

**Update Tool**
```bash
python cathaxor.py --update
```

### All Command Line Arguments
```text
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL (e.g. http://example.com)
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist file for parameters (Default: burp-parameter-names.txt)
  -t THREADS, --threads THREADS
                        Number of threads (Default: 30)
  -o OUTPUT, --output OUTPUT
                        Save output to file
  -d DELAY, --delay DELAY
                        Delay between requests in seconds (Default: 0)
  -H HEADER, --header HEADER
                        Custom Header (e.g. -H 'Authorization: Bearer token')
  -c COOKIES, --cookies COOKIES
                        Custom Cookies (e.g. 'session=123; user=admin')
  --update              Update the tool from GitHub
```

## Author
**Abdulla Rahaman**
