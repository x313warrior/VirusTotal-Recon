# VirusTotal Domain/Subdomain Batch Extractor

**Author:** [x313warrior](https://github.com/x313warrior)

A Python tool to fetch VirusTotal domain/subdomain reports in batch, extract IPs, subdomains, SHA256 hashes, and save the results for each domain/subdomain as a TXT file.

---

## Features

- Supports single domain (`-d`) or a list of domains/subdomains (`-l`)
- Rotates between **3 VirusTotal API keys** (every 4 requests)
- Outputs results for each domain/subdomain in `{domain_or_subdomain}_VirusTotal.txt`
- Extracts:
  - All resolved IP addresses
  - All subdomains
  - All SHA256 hashes (from samples and URLs)

---

## Requirements

- Python 3.6+
- `requests` library (`pip install requests`)

---

## Usage

### 1. Clone the Repo

```bash
git clone https://github.com/313warrior/virustotal-batch-extractor.git
cd virustotal-batch-extractor
```

### 2. Edit API Keys

Open `vt_batch_report_extractor.py` and add your 3 VirusTotal API keys in the `API_KEYS` list:

```python
API_KEYS = [
    "YOUR_API_KEY1",
    "YOUR_API_KEY2",
    "YOUR_API_KEY3"
]
```

### 3. For a Single Domain

```bash
python vt_batch_report_extractor.py -d domain.com
```

**Output:**  
Will create `domain_com_VirusTotal.txt` with extracted info.

---

### 4. For a List of Domains/Subdomains

- Create `subdomain.txt` with one domain/subdomain per line.

```bash
python vt_batch_report_extractor.py -l subdomain.txt
```

**Output:**  
Creates a TXT file for each entry, e.g.:
- `domain_com_VirusTotal.txt`
- `assets_domain_com_VirusTotal.txt`
- etc.

---

## Example Output

Each TXT file looks like:

```
ip
100.24.223.51
100.25.186.0
...

subdomain
assets.domain.com
regulated-documents.domain.com
...

sha256
95769eb326e23b8cd1b7a9b82d884a713a9724f49b2794ac5b967d8cd706de83
...
```

---

## Notes

- API key rotation helps to avoid VirusTotal API rate limits.
- The filename replaces `.` and `/` with `_` for compatibility.
- For large lists, the tool cycles through API keys automatically.

---

## License

MIT License

---

**Made by [x313warrior](https://github.com/x313warrior)**
