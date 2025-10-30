#!/usr/bin/env python3
import requests
import json
import argparse
import os
import sys

API_KEYS = [
    "XXXXXXXXXXXXXXX",
    "XXXXXXXXXXXXXXX",
    "XXXXXXXXXXXXXXX"
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
        print(f"Error for {domain}: {response.status_code} {response.text}", file=sys.stderr)
        return None

def format_output(data):
    """
    Produce output with only three sections in this order:
    1) ip      -> list of IPs from 'resolutions'
    2) sha256  -> list of sha256 hashes from undetected samples
    3) undetected_urls -> only the URL strings (one per line), no extra metadata
    Nothing else is included.
    """
    out = []

    # 1) IPs
    out.append("ip")
    for entry in data.get("resolutions", []):
        ip = entry.get("ip_address") or entry.get("ip") or ""
        if ip:
            out.append(ip)

    # 2) SHA256 hashes (collect from undetected_* sample lists)
    out.append("\nsha256")
    # undetected_downloaded_samples
    for entry in data.get("undetected_downloaded_samples", []):
        sha = entry.get("sha256", "")
        if sha:
            out.append(sha)
    # undetected_referrer_samples
    for entry in data.get("undetected_referrer_samples", []):
        sha = entry.get("sha256", "")
        if sha:
            out.append(sha)
    # undetected_communicating_samples
    for entry in data.get("undetected_communicating_samples", []):
        sha = entry.get("sha256", "")
        if sha:
            out.append(sha)

    # 3) Undetected URLs - only the URL strings, one per line
    out.append("\nundetected_urls")
    for entry in data.get("undetected_urls", []):
        # VirusTotal commonly returns lists like:
        # [url, sha256, positives, total, date]
        if isinstance(entry, list) and len(entry) > 0:
            url = entry[0]
            if url:
                out.append(url)
        elif isinstance(entry, dict):
            url = entry.get("url", "")
            if url:
                out.append(url)
        else:
            # fallback: stringify
            s = str(entry)
            if s:
                out.append(s)

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
    parser = argparse.ArgumentParser(description="Fetch VirusTotal domain reports and extract ip, sha256 and undetected URLs.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain/subdomain to check")
    group.add_argument("-l", "--list", help="File with list of domains/subdomains (one per line)")
    args = parser.parse_args()

    api_key_count = len(API_KEYS)

    if args.domain:
        api_key = API_KEYS[0]
        process_domain(args.domain.strip(), api_key)
    elif args.list:
        if not os.path.exists(args.list):
            print(f"List file not found: {args.list}", file=sys.stderr)
            return
        with open(args.list) as f:
            for idx, line in enumerate(f):
                domain = line.strip()
                if domain:
                    # Rotate API key every 4 requests
                    api_key = API_KEYS[(idx // 4) % api_key_count]
                    process_domain(domain, api_key)

if __name__ == "__main__":
    main()
