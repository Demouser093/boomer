# Bash Enumeration Tool

## Overview
This script is a powerful enumeration tool designed to help security researchers perform various reconnaissance tasks. It supports domain-to-IP resolution, CIDR enumeration, subdomain discovery, HTTP status code filtering, directory listing downloads, and much more.

---

## Features

- **Domain to IPs (`-a`)**: Resolves domains to their corresponding IP addresses.
- **CIDR to IPs (`-b`)**: Extracts all IPs from a given CIDR range.
- **CIDR to Domains (`-c`)**: Performs reverse DNS lookups on CIDR ranges.
- **HTTPX to Specific Status Code (`-d, -o`)**: Filters URLs based on HTTP response status codes.
- **Download Directory Listing (`-e`)**: Downloads files from directory listing-enabled websites.
- **Mass CNAME Lookup (`-f`)**: Extracts CNAME records for domains in a given file.
- **Mass Port Scan (`-g`)**: Scans for open ports using `naabu`.
- **AlienVault URLs (`-h`)**: Fetches URLs from AlienVault OTX.
- **VirusTotal Analysis (`-i`)**: Queries VirusTotal for domain reports.
- **All Domains (`-j`)**: Aggregates subdomains from multiple sources.
- **All URLs (`-k`)**: Collects URLs using different OSINT tools.
- **Domains to Status Codes (`-l, -n`)**: Categorizes domains based on their HTTP status codes.
- **ZipFinder (`-m`)**: Finds ZIP files from collected URLs.

---

## Installation

1. Install dependencies:
   ```sh
   sudo apt install prips jq
   ```
2. Install required tools from Go repositories:
   ```sh
   GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
   GO111MODULE=on go install -v github.com/tomnomnom/anew@latest
   ```

---

## Usage

Run the script with the desired option and input file.

### General Syntax
```sh
chmod +x script.sh
./script.sh [OPTION] [INPUT]
```

### Options

| Option | Description                                      | Example Usage                          |
|--------|--------------------------------------------------|----------------------------------------|
| `-a`   | Convert domains to IP addresses.                 | `./script.sh -a domains.txt` |
| `-b`   | Convert CIDR ranges to individual IPs.           | `./script.sh -b cidr.txt`    |
| `-c`   | Perform reverse DNS lookup on CIDR ranges.       | `./script.sh -c cidr.txt`    |
| `-d`   | Extract URLs with specific HTTP status codes.     | `./script.sh -d httpx.txt`   |
| `-e`   | Download content from directory listing websites.| `./script.sh -e http://example.com` |
| `-f`   | Resolve CNAME records for subdomains.            | `./script.sh -f subdomains.txt` |
| `-g`   | Perform mass port scanning.                      | `./script.sh -g targets.txt` |
| `-h`   | Scrape URLs from AlienVault OTX.                 | `./script.sh -h example.com` |
| `-i`   | Fetch undetected URLs from VirusTotal.           | `./script.sh -i example.com` |
| `-j`   | Enumerate subdomains using multiple tools.       | `./script.sh -j example.com` |
| `-k`   | Extract URLs using tools like `gau` and `waybackurls`. | `./script.sh -k example.com` |
| `-l`   | Filter domains by HTTP status codes.             | `./script.sh -l domains.txt` |
| `-m`   | Find ZIP files from collected URLs.              | `./script.sh -m urls.txt` |
| `-n`   | Categorize domains based on their HTTP status codes. | `./script.sh -n domains.txt` |
| `-o`   | Extract URLs with specific HTTP status codes.     | `./script.sh -o httpx.txt`   |

---

## Examples

1. **Convert domains to IPs:**
   ```sh
   ./script.sh -a domains.txt
   ```
2. **Expand CIDR ranges to IPs:**
   ```sh
   ./script.sh -b cidr.txt
   ```
3. **Scrape URLs from AlienVault OTX:**
   ```sh
   ./script.sh -h example.com
   ```
4. **Perform mass port scanning:**
   ```sh
   ./script.sh -g targets.txt
   ```
5. **Filter domains by HTTP status codes:**
   ```sh
   ./script.sh -l domains.txt
   ```

---

## Dependencies

- `jq`
- `prips`
- `wget`
- `naabu`
- `subfinder`
- `assetfinder`
- `waybackurls`
- `hakrawler`
- `gospider`
- `katana`
- `httpx`
- `dig`
- `curl`

---

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for legal and ethical use only. The authors are not responsible for any misuse or damage caused by this tool. Use it at your own risk.

