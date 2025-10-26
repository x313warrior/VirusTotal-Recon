import requests
import json
import argparse
import os

API_KEYS = [
    "API_KEY1_HERE",
    "API_KEY2_HERE",
    "API_KEY3_HERE"
]
BASE_URL = "https://virustotal.com/vtapi/v2/domain/report"

def fetch_report(domain, api_key):
    params = {
        'apikey': api_key,
        'domain': domain
    }
    response = requests.get(BASE_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error for {domain}: {response.status_code} {response.text}")
        return None

def format_output(data):
    out = []
    out.append("ip")
    for entry in data.get("resolutions", []):
        out.append(entry.get("ip_address", ""))
    out.append("\nsubdomain")
    for sub in data.get("subdomains", []):
        out.append(sub)
    out.append("\nsha256")
    for entry in data.get("undetected_downloaded_samples", []):
        out.append(entry.get("sha256", ""))
    for entry in data.get("undetected_referrer_samples", []):
        out.append(entry.get("sha256", ""))
    for entry in data.get("undetected_urls", []):
        out.append(entry[1])
    return '\n'.join(out)

def save_output(domain, output):
    fname = f"{domain.replace('.', '_').replace('/', '_')}_VirusTotal.txt"
    with open(fname, "w") as f:
        f.write(output)
    print(f"Saved: {fname}")

def process_domain(domain, api_key):
    data = fetch_report(domain, api_key)
    if data:
        output = format_output(data)
        save_output(domain, output)

def main():
    parser = argparse.ArgumentParser(description="Fetch VirusTotal domain reports and extract info.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain/subdomain to check")
    group.add_argument("-l", "--list", help="File with list of domains/subdomains (one per line)")
    args = parser.parse_args()

    api_key_count = len(API_KEYS)
    request_count = 0

    if args.domain:
        api_key = API_KEYS[0]
        process_domain(args.domain.strip(), api_key)
    elif args.list:
        if not os.path.exists(args.list):
            print(f"List file not found: {args.list}")
            return
        with open(args.list) as f:
            for idx, line in enumerate(f):
                domain = line.strip()
                if domain:
                    # Rotate API key every 4 requests
                    api_key = API_KEYS[(idx // 4) % api_key_count]
                    process_domain(domain, api_key)
                    request_count += 1

if __name__ == "__main__":
    main()
    
