# BX2Debug - Advanced Dynamic Malware Analysis Logger

`bx2debug` is a sophisticated reporting and data-enrichment layer built on top of the `bx2trace` dynamic analysis engine. It is designed to transform raw API hooks and memory dumps into clean, actionable, and analyst-friendly Threat Intelligence reports.

## Features

- **Executive Summary Generation:** Automatically derives a triage verdict (MALICIOUS, SUSPICIOUS, BENIGN) and highlights critical Key Findings (e.g., C2 domains, injected processes, encryption activity) at the very top of the report.
- **Advanced String Classification:** Extracts strings directly from memory and dynamically categorizes them into actionable Indicators of Compromise (IOCs) such as:
  - URLs & Domains
  - Network Indicators (IP Addresses)
  - Registry Keys
  - File Paths
  - Suspicious Commands (PowerShell, cmd, etc.)
- **Noise Reduction & False-Positive Filtering:** 
  - Automatically detects and discards x64 assembly prologue/epilogue artifacts (e.g., `UAWAVAUATWVSH`) from memory string dumps.
  - Smartly differentiates between actual IP addresses and .NET/Windows assembly version numbers (e.g., `4.0.0.0` or `5.9.0.0`).
  - Purges `DecodeError` trace failures to ensure report integrity.
- **Cross-Referenced Network IOCs:** Links DNS queries (`DNS_LOOKUP`) to raw TLS payloads (`DATA_SENT`) to reconstruct full network context, and extracts domains directly from executed shell command arguments.
- **Cryptographic Context:** Infers cryptographic key algorithms (e.g., AES, RSA PUBLICKEYBLOB) based on `CryptImportKey` blob sizes.

## Project Structure

- `main.py`: The entry point for the analysis wrapper.
- `storage/json_logger.py`: The core reporting engine that builds the structured JSON report and Executive Summary in real-time.
- `enrichment/string_classifier.py`: The regex-based heuristic engine for classifying raw memory strings.
- `reports/`: Directory where the final `.json` analysis reports are saved (ignored by git).

## Future Roadmap (Phase 3)

The next phase of development focuses on accessibility and intelligence:
1. **Graphical User Interface (GUI):** A modern, sleek desktop interface to select targets, configure trace options, and visualize the generated reports interactively.
2. **AI Integration:** Integrating an AI assistant to automatically read the JSON reports and provide human-readable explanations of the malware's behavior, intent, and potential impact.
