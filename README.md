# 🛡️ BX2Debug: Advanced Dynamic Malware Analysis & IOC Enrichment Engine

## 📖 Overview

**BX2Debug** is a sophisticated reporting and data-enrichment layer built on top of the `bx2trace` dynamic analysis engine. While raw API monitors generate massive amounts of unstructured, noisy data, BX2Debug acts as an intelligent funnel. It intercepts raw memory traces, API hooks, and network streams in real-time, processes them through a custom heuristic engine, and outputs a clean, actionable **Threat Intelligence Report** formatted in JSON.

This tool is designed specifically for Malware Analysts and Security Researchers who need to quickly triage a suspicious executable without drowning in assembly code or raw hexadecimal dumps.

---

## 🎯 The Problem & Our Solution

**The Problem:** Traditional dynamic analysis tools often output raw memory buffers, garbled strings, and unstructured API calls. Analysts spend hours manually filtering out false positives (like .NET assembly version numbers mistaken for IPs) or trying to correlate a DNS lookup with a subsequent encrypted network stream.

**The Solution:** BX2Debug automates the triage process. It intelligently filters out noise, cross-references related events, and instantly flags malicious behavior. The final output is an "Analyst-Ready" report that immediately highlights the most critical Indicators of Compromise (IOCs).

---

## ✨ Core Features

### 1. Intelligent IOC Extraction & Enrichment
- **Dynamic String Classification:** Automatically extracts memory strings and uses advanced Regex patterns to categorize them into actionable buckets: `URLs`, `Network Indicators (IPs)`, `Registry Keys`, `File Paths`, and `Suspicious Commands` (e.g., PowerShell, cmd).
- **Embedded URL Extraction:** Capable of scanning executed shell commands and process launch arguments to extract hidden URLs, ensuring that C2 domains passed via command-line arguments are always captured.

### 2. Advanced Noise Reduction Engine
- **Garbage Filtering:** Detects and discards x64 assembly prologue/epilogue artifacts (e.g., `UAWAVAUATWVSH`) that often pollute raw memory string dumps.
- **False-Positive Mitigation:** Implements logic to distinguish between actual IPv4 network addresses and Microsoft .NET assembly version numbers (e.g., `4.0.0.0`, `13.0.0.0`), preventing report corruption.
- **API Failure Handling:** Safely intercepts and sanitizes internal tracer failures (like `DecodeError`), ensuring they do not bleed into the final intelligence report.

### 3. Contextual Network Correlation
- **DNS to Payload Linking:** Automatically tracks `DNS_LOOKUP` events and correlates them with subsequent `DATA_SENT` streams on the same socket. This allows the tool to definitively state *where* encrypted TLS data is being sent.

### 4. Cryptographic Activity Analysis
- Monitors `CryptImportKey`, `BCryptEncrypt`, and `BCryptDecrypt` API calls.
- Dynamically infers the type of cryptographic key being used (e.g., `AES-256`, `RSA PUBLICKEYBLOB`) based on the byte length of the imported key payload.

### 5. Automated Triage & Executive Summary
The system automatically assigns a risk level based on observed behavior:
- 🔴 **MALICIOUS:** Process Injection, PE File Dropping, or Known C2 Connections.
- 🟡 **SUSPICIOUS:** High volume of network connections, registry modifications, or anti-debug techniques.
- 🟢 **BENIGN:** No significant security alerts triggered.

---

## 🏗️ Project Architecture

The tool is modular and designed for high performance:

- `main.py`: The application entry point. Handles the target execution environment and initializes the logger.
- `storage/json_logger.py`: The core tracking engine. Maintains state across the lifecycle of the malware execution, deduplicates events, links network contexts, and builds the final JSON report.
- `enrichment/string_classifier.py`: The heuristic classification module. Contains the logic for categorizing strings and filtering out assembly garbage and false positives.
- `reports/`: The directory where the structured `.json` intelligence reports are saved.

---

## 📊 Example Output (Executive Summary)

When a piece of malware is analyzed, BX2Debug generates a clear, prioritized summary at the very top of the report:

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

---

## 🚀 Future Roadmap (Phase 3)

The current version (Phase 2) successfully establishes a robust backend data pipeline. The next phase of development will focus on accessibility and advanced intelligence:

1. **Graphical User Interface (GUI):** A sleek, modern desktop interface to allow analysts to select target executables, configure hooking options, and visualize the JSON reports through interactive dashboards and process trees.
2. **AI Integration:** Integrating Large Language Models (LLMs) to automatically read the generated JSON reports and provide a human-readable, plain-English explanation of the malware's intent and potential impact.
