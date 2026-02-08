# Tarahunter v1.0.0 "Chitin Shell"

**Tarahunter** is a high-speed, multi-threaded APT hunting tool designed for lateral movement detection and forensic artifact discovery in Windows environments via SMB. The tool is initially based on Taraqan Scanner - https://github.com/but43r/Taraqan. 

## Key Features
* **Pass-the-Hash (PtH):** Authenticate using NTLM hashes without needing plain-text passwords.
* **Targeted Scanning:** Hunt recursively in specific locations defined via YAML (e.g., `C$\Users\Public`, `ProgramData`).
* **Wildcard Support:** Automatically expand user profiles using `*` in paths (e.g., `C$\Users\*\Desktop`).
* **IOC Matching:** * **Filename Patterns:** Hunt for tools like Mimikatz, SharpHound, or Chisel.
    * **SHA256 Hashes:** Verify file integrity against known malware signatures.
    * **Double Extensions:** Detect suspicious files like `report.pdf.exe`.
* **Multi-threaded:** Fast concurrent scanning of entire CIDR ranges.

## Configuration (`hunt.yaml`)
Define your rules in a simple YAML format:
```yaml
apt_rules:
  file_patterns:
    - "*mimikatz*"
    - "*sharphound*"
    - "*adfind*"
    - "lsass*.dmp"
    - "nc.exe"
    - "chisel*"
    - "temp.ps1"
    - "setup.exe.config"
  check_double_extensions: false
  ioc_hashes:
    - "92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50"

targeted_locations:
  - "C$\\Users\\Public"
  - "C$\\ProgramData"
  - "C$\\Users\\*\\Downloads"
  - "C$\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
```

## Usage 

First thing first you need to build the code: 

```bash
go build -o tarahunter main.go
```

Basic scan (password)

```bash
./tarahunter -t 10.0.0.0/8 -u Administrator -d CORP -p P@ssw0rd123
```

Scan with PtH + Custom YAML config with artifact download

```bash
./tarahunter -t 10.1.0.0/24 -u Administrator -d CORP -H <NT_HASH> -c your_hunt_config.yaml --download
```
