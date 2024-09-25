# 🛡️ Threat Intelligence Repository

![Python](https://img.shields.io/badge/python-100%25-yellow.svg) ![ThreatIntel](https://img.shields.io/badge/Threat%20Intel-Malicious%20IOC%20Repository-red.svg) ![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

Welcome to the **Threat Intelligence Repository**! This repository contains **Malicious Indicator of Compromise (IOC)** data, which is vital for cybersecurity professionals to enhance threat detection and improve incident response capabilities.

---

## 📁 Repository Structure

- **APT Groups**: Updated with new IOCs.
- **Ransomware**: Fresh IOCs added regularly.
- **CVE**: Latest CVEs identified and false positives removed.
- **Threat Groups**: IOC details for well-known threat groups.
- **DGA**: Domain generation algorithm-based IOCs.
- **Multiple Malware IOC Files**: Includes IOCs for **3CX Supply Chain Attack**, **Agent Tesla**, **AsyncRAT**, **BazarLoader**, **Cobalt Strike**, **Dridex**, and many more.

Each file contains a comprehensive list of Indicators of Compromise, such as:
- **IP addresses**
- **Domains**
- **URLs**
- **File hashes (MD5, SHA1, SHA256)**

---

## 💻 How to Use

These IOCs can be used for:
1. **Integrating with security tools**: Automate threat detection by importing these IOCs into your SOC or SIEM.
2. **Manual analysis**: Dive into each IOC to understand ongoing threats and refine your defense strategy.
3. **Collaboration**: Share these IOCs with other organizations or threat intelligence platforms for collective defense against malicious actors.

### 📜 Example Usage
1. Download the repository.
2. Use the IOCs in your tools like **Suricata**, **Zeek**, or **Threat Intelligence Platforms (TIPs)**.
3. Integrate them into your **Intrusion Detection Systems (IDS)** or **Endpoint Detection and Response (EDR)** solutions.

---

## 🙌 Contributing

We highly encourage contributions from the community! Whether it's adding new IOCs, removing false positives, or updating existing entries, your contributions are welcome.

### Steps to Contribute:
1. **Fork the repository**.
2. **Add or update IOCs**.
3. **Submit a pull request** with a detailed description and source for the IOCs.

---

## 🔥 Example Files
- **AZORult.txt**: Newly added IOCs.
- **Formbook.txt**: Contains recent threats discovered in the wild.
- **BumbleBee.txt**: False positives removed.
- **Dridex.txt**: IOCs added from the Feodo tracker.
- **Emotet.txt**: Cloudflare, Google, and Microsoft IPs removed.
- **QakBot.txt**: Recently updated with active threats.

These files are regularly updated with the latest threat intelligence!

---

## ⚠️ Disclaimer

This repository is for **informational purposes only**. We do not condone or support any malicious activity using the IOCs provided here. The authors are not liable for any misuse of this data. Use this repository responsibly and for legitimate security practices only.

---

## ⭐️ Features

- **Stay Updated**: Latest IOCs for malware, ransomware, and APT groups.
- **Collaborative Effort**: Contributions from the cybersecurity community.
- **IOC Categories**: Structured files for easy parsing and integration into tools.
- **False Positives Removed**: Continuous cleanup and verification of data.

---

## 📦 Technologies Used

- **Python**: For parsing and cleaning up IOCs.
- **JSON/MISP**: Some IOC feeds are provided in JSON format for integration with MISP.

---

## 🤝 Community

Join our community of cybersecurity professionals and threat hunters to help us keep the world safe from cyber threats!

---

**Thank you for using the Threat Intelligence Repository! Protect. Detect. Defend.**
