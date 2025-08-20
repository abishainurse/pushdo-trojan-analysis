# Pushdo Trojan Incident Analysis

## Overview
This case study documents the analysis of a simulated malware infection involving the Pushdo Trojan. Using a Security Onion environment, I investigated suspicious alerts, identified indicators of compromise (IOCs), and validated malicious files with threat intelligence tools. The objective was to demonstrate practical network forensics and incident response skills.

## Tools & Environment
- **Security Onion (Sguil & Kibana):** Alert collection and analysis
- **Wireshark:** Packet capture review
- **NetworkMiner:** Host and artifact extraction
- **VirusTotal:** Hash-based malware verification
- **Threat Intel Sources:** Open-source research on domains and IPs

## Investigation Steps

### 1. Verify Services and System Status
- Ensured all systems were operating using the Linux command line.
<img src="https://i.imgur.com/TfjWRBW.png" height="80%" width="80%" alt="Linux Line showing Status"/>

### 1. Initial Alerts
- Date/Time of infection: **June 27, 2017, 13:38–13:44 UTC**
- Compromised Host:
  - **IP:** 192.168.1.96
  - **MAC:** 00:15:C5:DE:C7:3B (Dell Inc.)

**Screenshot placeholder:** `images/security_onion_alerts.png`

### 2. Infection Vector
- Infection occurred through an **HTTP request** disguised as a legitimate download.
- IDS flagged multiple suspicious alerts, including:
  - `ET TROJAN Backdoor.Win32.Pushdo.s Checkin`
  - `ET TROJAN Pushdo.S CnC response`
  - `ET POLICY PE EXE or DLL Windows file download HTTP`

**Screenshot placeholder:** `images/wireshark_http_request.png`

### 3. Malicious Files Identified
Two executables were downloaded by the infected host:

- **gerv.gun**
  - SHA256: `0931537889c35226d00ed26962ecacb140521394279eb2ade7e9d2afcf1a7272`
  - Detected by 60+ antivirus engines
  - File type: Win32 executable (~236 KB)

- **trow.exe**
  - SHA256: `94a0a09ee6a21526ac34d41eabf4ba603e9a30c26e6a1dc072ff45749dfb1fe1`
  - Detected by 66+ antivirus engines
  - File type: Win32 executable (~323 KB)

**Screenshot placeholders:**
- `images/virustotal_gerv.png`
- `images/virustotal_trow.png`

### 4. Malicious Infrastructure
- **Domains contacted:**
  - `lounge-haarstudio.nl`
  - `mattied.com`

- **Suspicious External IPs:**
  - `119.28.70.207`
  - `143.95.151.192`
  - `208.67.222.222` (OpenDNS lookup)
  - `208.83.22.34`

**Screenshot placeholder:** `images/networkminer_ips.png`

### 5. Command-and-Control (C2) Activity
- After infection, the host attempted to contact **C2 servers**.
- Alerts confirmed both initial check-in and C2 response traffic.

**Screenshot placeholder:** `images/c2_alerts.png`

## Findings
- A workstation accessed a malicious webpage, leading to **Pushdo trojan infection**.
- The malware downloaded additional payloads (`gerv.gun`, `trow.exe`).
- Both files were confirmed malicious through **hash analysis and VirusTotal**.
- The compromised host engaged in **C2 communication**, confirming active compromise.

## Recommendations
1. **Web Filtering:** Block downloads of executables from untrusted domains.
2. **Intrusion Detection:** Ensure IDS rules cover suspicious HTTP requests and executable transfers.
3. **Endpoint Security:** Deploy EDR to detect abnormal file execution.
4. **Threat Intelligence Integration:** Monitor known Pushdo-related IOCs.
5. **User Awareness Training:** Reduce risk of drive-by download infections.

## Conclusion
This case study highlights the value of layered security monitoring. By correlating IDS alerts, packet captures, and threat intelligence, I was able to identify, confirm, and analyze a Pushdo trojan infection within a simulated SOC environment.
