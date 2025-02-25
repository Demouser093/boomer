# Multi-Tool: Domain and Network Reconnaissance Toolkit

A versatile command-line tool for domain and network reconnaissance. This tool combines multiple functionalities into a single script, making it easy to perform tasks like domain-to-IP conversion, CIDR expansion, reverse DNS lookups, HTTP status code extraction, directory downloads, mass CNAME resolution, port scanning, and more. Ideal for penetration testers, bug bounty hunters, and network administrators.

---

## Features

- **Domain to IP Conversion**: Resolve domains to their corresponding IP addresses.
- **CIDR to IP Expansion**: Convert CIDR ranges into individual IP addresses.
- **CIDR to Domain**: Perform reverse DNS lookups on CIDR ranges to find associated domains.
- **HTTP Status Code Extraction**: Extract URLs with specific HTTP status codes from `httpx` output.
- **Directory Listing Download**: Download content from websites with directory listing enabled.
- **Mass CNAME Resolution**: Resolve CNAME records for a list of subdomains.
- **Mass Port Scanning**: Perform port scanning on a list of domains or IPs.
- **AlienVault URL Scraping**: Scrape URLs associated with a domain from AlienVault OTX.
- **VirusTotal Integration**: Fetch undetected URLs for a domain from VirusTotal.
- **Domain Enumeration**: Gather subdomains using multiple tools (e.g., `crtsh`, `subfinder`, `assetfinder`).
- **URL Enumeration**: Extract URLs using tools like `gau`, `waybackurls`, and `hakrawler`.
- **Clean Domains**: Filter domains by HTTP status codes (200, 300, 400, 500).

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name
   ```

2. Make the script executable:
   ```bash
   chmod +x your_script_name.sh
   ```

3. Install dependencies:
   ```bash
   ./setup.sh
   ```

---

## Usage

Run the script with the desired option and input file or domain.

### General Syntax
```bash
./your_script_name.sh [OPTION] [INPUT]
```

### Options

| Option | Description                                      | Example Usage                          |
|--------|--------------------------------------------------|----------------------------------------|
| `-a`   | Convert domains to IP addresses.                 | `./your_script_name.sh -a domains.txt` |
| `-b`   | Convert CIDR ranges to individual IPs.           | `./your_script_name.sh -b cidr.txt`    |
| `-c`   | Perform reverse DNS lookup on CIDR ranges.       | `./your_script_name.sh -c cidr.txt`    |
| `-d`   | Extract URLs with specific HTTP status codes.     | `./your_script_name.sh -d httpx.txt`   |
| `-e`   | Download content from directory listing websites.| `./your_script_name.sh -e http://example.com` |
| `-f`   | Resolve CNAME records for subdomains.            | `./your_script_name.sh -f subdomains.txt` |
| `-g`   | Perform mass port scanning.                      | `./your_script_name.sh -g targets.txt` |
| `-h`   | Scrape URLs from AlienVault OTX.                 | `./your_script_name.sh -h example.com` |
| `-i`   | Fetch undetected URLs from VirusTotal.           | `./your_script_name.sh -i example.com` |
| `-j`   | Enumerate subdomains using multiple tools.       | `./your_script_name.sh -j example.com` |
| `-k`   | Extract URLs using tools like `gau` and `waybackurls`. | `./your_script_name.sh -k example.com` |
| `-l`   | Filter domains by HTTP status codes.             | `./your_script_name.sh -l domains.txt` |

---

## Examples

1. **Convert domains to IPs:**
   ```bash
   ./your_script_name.sh -a domains.txt
   ```

2. **Expand CIDR ranges to IPs:**
   ```bash
   ./your_script_name.sh -b cidr.txt
   ```

3. **Scrape URLs from AlienVault OTX:**
   ```bash
   ./your_script_name.sh -h example.com
   ```

4. **Perform mass port scanning:**
   ```bash
   ./your_script_name.sh -g targets.txt
   ```

5. **Filter domains by HTTP status codes:**
   ```bash
   ./your_script_name.sh -l domains.txt
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

All dependencies are automatically installed by the `setup.sh` script.

---

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for legal and ethical use only. The authors are not responsible for any misuse or damage caused by this tool. Use it at your own risk.
