<div align="center">
  <h1>🛡️ BX2Debug</h1>
  <p><strong>Advanced Dynamic Malware Analysis & IOC Enrichment Engine</strong></p>

  <p>
    <a href="https://github.com/fareed1-ataf/BX2debug/issues"><img alt="Issues" src="https://img.shields.io/github/issues/fareed1-ataf/BX2debug?color=blue&style=flat-square" /></a>
    <a href="https://github.com/fareed1-ataf/BX2debug/network/members"><img alt="Forks" src="https://img.shields.io/github/forks/fareed1-ataf/BX2debug?color=blue&style=flat-square" /></a>
    <a href="https://github.com/fareed1-ataf/BX2debug/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/fareed1-ataf/BX2debug?color=blue&style=flat-square" /></a>
    <a href="https://github.com/fareed1-ataf/BX2debug/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/fareed1-ataf/BX2debug?color=blue&style=flat-square" /></a>
    <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/Python-3.11+-blue.svg?style=flat-square&logo=python" /></a>
  </p>
</div>

<br />

## 📑 Table of Contents
- [About The Project](#-about-the-project)
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Understanding The Reports](#-understanding-the-reports)
- [Architecture](#-architecture)
- [Roadmap (Phase 3)](#-roadmap)
- [License](#-license)

---

## 📖 About The Project

**BX2Debug** is a sophisticated reporting and data-enrichment layer built on top of the `bx2trace` dynamic analysis engine. While raw API monitors generate massive amounts of unstructured, noisy data, BX2Debug acts as an intelligent funnel. It intercepts raw memory traces, API hooks, and network streams in real-time, processes them through a custom heuristic engine, and outputs a clean, actionable **Threat Intelligence Report** formatted in JSON.

This tool is designed specifically for **Malware Analysts** and **Security Researchers** who need to quickly triage suspicious executables without drowning in assembly code or raw hexadecimal dumps.

---

## ✨ Key Features

### 🔍 Intelligent IOC Extraction
- **Dynamic String Classification:** Automatically extracts memory strings and categorizes them into actionable buckets: `URLs`, `IPs`, `Registry Keys`, `File Paths`, and `Suspicious Commands`.
- **Embedded URL Extraction:** Scans executed shell commands to extract hidden URLs, ensuring C2 domains passed via command-line arguments are captured.

### 🛡️ Advanced Noise Reduction
- **Garbage Filtering:** Detects and discards x64 assembly artifacts (e.g., `UAWAVAUATWVSH`) that pollute raw memory dumps.
- **False-Positive Mitigation:** Distinguishes between actual IPv4 addresses and Microsoft .NET assembly version numbers (e.g., `4.0.0.0`).
- **API Failure Handling:** Sanitizes internal tracer failures (like `DecodeError`) so they do not bleed into the intelligence report.

### 🌐 Contextual Network Correlation
- Automatically tracks `DNS_LOOKUP` events and correlates them with subsequent `DATA_SENT` streams on the same socket to definitively identify TLS destinations.

### 🔐 Cryptographic Analysis
- Monitors `CryptImportKey`, `BCryptEncrypt`, and `BCryptDecrypt`.
- Dynamically infers the cryptographic key algorithm (e.g., `AES-256`, `RSA PUBLICKEYBLOB`) based on byte length.

### ⚡ Automated Triage
Assigns a risk level based on observed behavior:
- 🔴 **MALICIOUS:** Process Injection, PE File Dropping, or Known C2 Connections.
- 🟡 **SUSPICIOUS:** High volume of network connections, registry modifications, or anti-debug techniques.
- 🟢 **BENIGN:** No significant security alerts.

---

## 💻 Installation

### Prerequisites
- Python 3.11 or higher
- Windows OS (Required for dynamic tracing capabilities)

### Setup
1. Clone the repository:
   ```cmd
   git clone https://github.com/fareed1-ataf/BX2debug.git
   cd BX2debug
   ```
2. Install required dependencies:
   ```cmd
   pip install -r requirements.txt
   ```

---

## 🚀 Usage

Run the tool against any suspicious executable. The analysis engine will launch the target, attach the tracer, and generate a report in real-time.

```cmd
python main.py
```
*(Note: A target file prompt will appear, or you can modify `main.py` to accept CLI arguments in future updates).*

Press `Ctrl+C` to cleanly detach the tracer and finalize the report.

---

## 📊 Understanding The Reports

Reports are automatically saved in the `reports/` directory. Each report features an **Executive Summary** at the top for instant triage:

```json
"Executive Summary": {
  "Verdict": "MALICIOUS",
  "Risk Level": "CRITICAL",
  "Key Findings": [
    "Anti-analysis evasion detected: IsDebuggerPresent",
    "Contacts external domain(s): malicious-c2-server.com",
    "Sends encrypted data over TLS 1.0 -> malicious-c2-server.com",
    "Decrypts data in memory (4 calls using RSA (PUBLICKEYBLOB))",
    "Spawns child process(es): powershell.exe"
  ],
  "Total Alerts": 17,
  "Analysis Time": "2026-09-24 05:01:04"
}
```
The report also contains detailed sections for:
- Process Tree & Injections
- File & Registry Activity
- Cryptographic Operations
- Full Memory String Analysis

---

## 🏗️ Architecture

The tool is highly modular:
- `main.py`: Application entry point.
- `storage/json_logger.py`: The core tracking engine. Maintains state, deduplicates events, links network contexts, and builds the JSON report.
- `enrichment/string_classifier.py`: The heuristic classification module. Contains logic for categorizing strings and filtering out assembly garbage.

---

## 🗺️ Roadmap

We are currently in **Phase 2** (Data Enrichment & Pipeline Optimization). 

**Upcoming in Phase 3:**
- [ ] **Graphical User Interface (GUI):** A modern desktop interface for interactive report visualization and process tree graphs.
- [ ] **AI Assistant Integration:** Integration with Large Language Models (LLMs) to automatically read JSON reports and provide plain-English malware analysis summaries.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
