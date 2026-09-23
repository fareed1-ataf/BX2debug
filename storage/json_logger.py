import os
import json
import time
import threading
from datetime import datetime
from bx2debug.utils.encoders import CustomJSONEncoder
from bx2debug.enrichment.string_classifier import StringClassifier


# Access flags for CreateFile — maps raw DWORD bits to human-readable names.
# Source: winnt.h / Microsoft documentation.
_FILE_ACCESS_FLAGS = {
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
    0x00100000: "SYNCHRONIZE",
    0x00020000: "DELETE",
    0x00040000: "READ_CONTROL",
    0x00080000: "WRITE_DAC",
    0x00000001: "FILE_READ_DATA",
    0x00000002: "FILE_WRITE_DATA",
    0x00000004: "FILE_APPEND_DATA",
    0x00000020: "FILE_EXECUTE",
}


def _decode_access_flags(access_val) -> list:
    """Convert a raw access DWORD to a list of human-readable flag names."""
    if isinstance(access_val, list):
        # Already decoded upstream — check if any element is a hex string needing decode
        result = []
        for item in access_val:
            if isinstance(item, str) and item.startswith("0x"):
                try:
                    val = int(item, 16)
                    matched = [name for mask, name in _FILE_ACCESS_FLAGS.items() if val & mask]
                    result.extend(matched if matched else [item])
                except ValueError:
                    result.append(item)
            else:
                result.append(item)
        return result if result else access_val
    if isinstance(access_val, int):
        matched = [name for mask, name in _FILE_ACCESS_FLAGS.items() if access_val & mask]
        return matched if matched else [hex(access_val)]
    return [str(access_val)]


class JsonLogger:
    """
    Builds a structured, analyst-friendly behavioral report in memory
    and saves it as a categorized JSON file.

    Design principles:
    - Each report section is purpose-built for a specific analyst workflow.
    - Raw CPU register dumps (args: rcx, rdx, ...) never appear in clean sections.
    - Only payload["details"] — the already-decoded, human-readable content — is stored.
    - THREAD events are never written to the report (no analytical value).
    - Analysis End Time is always updated so it reflects the last known state.
    """

    # Sentinel values that bx2trace emits when it cannot decode a string from memory.
    # These must never appear as data in the final analyst report.
    _BAD_VALUES = frozenset({"DecodeError", "decodeerror", "?", "", "unknown", "Unknown"})

    @staticmethod
    def _clean(value: str, fallback: str = None) -> str:
        """
        Returns value if it is a meaningful non-error string, else fallback.
        Used to strip bx2trace decode failures before writing to the report.
        """
        if not isinstance(value, str) or value.strip() in JsonLogger._BAD_VALUES or not value.strip():
            return fallback
        return value.strip()

    @staticmethod
    def _guess_key_type(key_len: int) -> str:
        """Infer cryptographic key algorithm from key blob length."""
        mapping = {
            16:  "AES-128",
            24:  "3DES / AES-192",
            32:  "AES-256",
            128: "RSA-1024",
            148: "RSA (PUBLICKEYBLOB)",
            256: "RSA-2048",
            512: "RSA-4096",
        }
        return mapping.get(key_len, f"Unknown ({key_len} bytes)")

    def __init__(self, target_path, mode="FULL_TRACE", output_path=None):
        self.target_path = target_path
        self.target_name = os.path.basename(target_path)
        self.mode = mode
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Tracks last DNS hostname so DATA_SENT events can name their destination
        self._last_dns_host = None

        if output_path:
            self.output_path = output_path
        else:
            log_dir = "reports"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_path = os.path.join(log_dir, f"report_{self.target_name}_{timestamp}.json")

        self.report = {
            "Executive Summary": {},
            "Analysis Metadata": {
                "Target Name":           self.target_name,
                "Target Path":           os.path.abspath(target_path),
                "Analysis Start Time":   self.start_time,
                "Analysis End Time":     None,
                "Execution Mode":        mode,
                "Total Events Captured": 0,
            },
            "Summary": {
                "Network Connections":   0,
                "Unique IPs":            [],
                "Unique Domains":        [],
                "Files Written":         0,
                "Files Deleted":         0,
                "Registry Modifications": 0,
                "Processes Spawned":     [],
                "Security Alerts":       0,
                "Strings Extracted":     0,
                "Verdict":               "UNKNOWN",
            },
            "Process Tree":                  [],
            "Executed Scripts & Commands": {
                "Shell Executions": [],
                "Process Launches": [],
                "COM Activations":  [],
            },
            "Loaded Modules (DLLs)":         [],
            "Security Alerts":               [],
            "Network Activity":              [],
            "Cryptographic Activity": {
                "Keys Imported":       0,
                "Encryption Calls":    0,
                "Decryption Calls":    0,
                "Crypto APIs Used":    [],
            },
            "Anti-Analysis Techniques":      [],
            "File System Activity":          [],
            "Registry Activity":             [],
            "Process & Injection Activity":  [],
            'Memory Analysis & Strings':     {
                "URLs": [],
                "File Paths": [],
                "Network Indicators": [],
                "Registry Keys": [],
                "Suspicious Commands": [],
                "Miscellaneous": []
            },
            "Raw Captured Data":             [],
        }

        self.lock = threading.Lock()
        self.processes_map = {}
        self._ioc_ips = set()
        self._ioc_domains = set()
        self.string_classifier = StringClassifier()
        self._extracted_strings_set = set()
        
        # Throttling state to avoid disk I/O on every single event
        self._event_count = 0
        self._last_save_time = time.time()
        self.SAVE_INTERVAL_EVENTS = 500
        self.SAVE_INTERVAL_SECONDS = 10.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, event):
        """
        Routes a single TraceEvent into the appropriate report section(s).
        All enum values are normalized to strings at the very beginning so
        every downstream check can use plain string comparisons safely.
        """
        with self.lock:
            # Normalize all enum fields to plain strings immediately.
            ecat = getattr(event, 'category', 'OTHER')
            eact = getattr(event, 'action',   'EVENT')
            sev  = getattr(event, 'severity', 'INFO')
            pid  = getattr(event, 'pid', 0)
            payload = getattr(event, 'payload', {}) or {}

            if hasattr(ecat, 'name'): ecat = ecat.name
            if hasattr(eact, 'name'): eact = eact.name
            if hasattr(sev,  'name'): sev  = sev.name

            # Skip THREAD events entirely — they carry no analytical value.
            if ecat == "THREAD":
                return

            self.report["Analysis Metadata"]["Total Events Captured"] += 1
            self._event_count += 1
            
            # Keep End Time current on every event so a hard-kill still leaves a timestamp.
            self.report["Analysis Metadata"]["Analysis End Time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            ts = datetime.now().strftime("%H:%M:%S")

            # ------------------------------------------------------------------
            # Route: HOOK_PLACED noise -> Raw only (never in clean sections)
            # ------------------------------------------------------------------
            if ecat == "SECURITY" and eact == "HOOK_PLACED":
                return

            # ------------------------------------------------------------------
            # ------------------------------------------------------------------
            # Route: Executed Scripts & Commands / COM
            # ------------------------------------------------------------------
            if ecat == "SCRIPT" and eact == "SHELL_EXECUTE":
                details = payload.get('details', {})
                target = self._clean(details.get("file", ""), fallback="[Could Not Decode]")
                self.report["Executed Scripts & Commands"]["Shell Executions"].append({
                    "PID":         pid,
                    "Target":      target,
                    "Arguments":   self._clean(details.get("params", ""), fallback=""),
                    "Verb":        details.get("verb", "open"),
                    "Working Dir": details.get("directory", ""),
                    "Timestamp":   ts,
                })
                # IOC: if target is a URL, extract and track the domain
                if target and target != "[Could Not Decode]":
                    self._extract_url_ioc(target)

            if ecat == "API" and payload.get('api') in ("CreateProcessW", "CreateProcessA"):
                details = payload.get('details', {})
                app  = self._clean(details.get("app_name", ""),     fallback="[Could Not Decode]")
                cmd  = self._clean(details.get("command_line", ""), fallback="[Could Not Decode]")
                self.report["Executed Scripts & Commands"]["Process Launches"].append({
                    "PID":          pid,
                    "App Name":     app,
                    "Command Line": cmd,
                    "Timestamp":    ts,
                })
                # IOC: if command line contains a URL, extract and track the domain
                if cmd and cmd != "[Could Not Decode]":
                    self._extract_url_ioc(cmd)
            
            if ecat == "COM" and eact == "COM_CREATED":
                details = payload.get('details', {})
                clsid = details.get("clsid", "?")
                if clsid not in self.report["Executed Scripts & Commands"]["COM Activations"]:
                    self.report["Executed Scripts & Commands"]["COM Activations"].append(clsid)

            # ------------------------------------------------------------------
            # Route: Process Tree
            # ------------------------------------------------------------------
            if ecat == "PROCESS" and eact == "CREATED":
                proc_info = {
                    "Process ID":   pid,
                    "Process Path": payload.get('path', 'Unknown'),
                    "Command Line": payload.get('command_line', ''),
                    "Parent PID":   payload.get('parent_pid', 0),
                    "Status":       "Running",
                    "Child Processes": [],
                }
                self.processes_map[pid] = proc_info
                parent_pid = payload.get('parent_pid', 0)
                if not payload.get('is_root') and parent_pid in self.processes_map:
                    self.processes_map[parent_pid]["Child Processes"].append(proc_info)
                else:
                    self.report["Process Tree"].append(proc_info)

                # IOC tracking
                proc_name = os.path.basename(payload.get('path', ''))
                if proc_name and proc_name not in ("DecodeError", "") and proc_name not in self.report["Summary"]["Processes Spawned"]:
                    self.report["Summary"]["Processes Spawned"].append(proc_name)

                self._save_to_disk()
                return

            if ecat == "PROCESS" and eact == "EXITED":
                if pid in self.processes_map:
                    self.processes_map[pid]["Status"] = f"Exited (Code: {payload.get('exit_code', 'N/A')})"
                self._save_to_disk()
                return

            # ------------------------------------------------------------------
            # Route: DLLs
            # ------------------------------------------------------------------
            if ecat == "DLL" and eact == "LOADED":
                base = payload.get('base_address', 0)
                self.report["Loaded Modules (DLLs)"].append({
                    "Process ID":   pid,
                    "DLL Path":     payload.get('path', 'Unknown'),
                    "Base Address": hex(base) if isinstance(base, int) else str(base),
                })
                self._save_to_disk()
                return

            # ------------------------------------------------------------------
            # Route: Memory Strings
            # ------------------------------------------------------------------
            if eact in ("STRING_FOUND", "NEW_STRINGS_FOUND", "RWX_STRINGS_DETECTED"):
                found = payload.get('strings', [])
                added = 0
                mem_strings = self.report.get("Memory Analysis & Strings", {})
                if not isinstance(mem_strings, dict):
                    mem_strings = {}
                    self.report["Memory Analysis & Strings"] = mem_strings

                for s in found:
                    str_val = s.get("string", str(s)) if isinstance(s, dict) else str(s)
                    if len(str_val) < self.string_classifier.MIN_LENGTH:
                        continue
                    
                    if str_val not in self._extracted_strings_set:
                        self._extracted_strings_set.add(str_val)
                        added += 1
                        
                        # Classify on the fly
                        if self.string_classifier.URL_PATTERN.search(str_val):
                            mem_strings.setdefault("URLs", []).append(str_val)
                        elif self.string_classifier.IP_PATTERN.match(str_val.strip()):
                            mem_strings.setdefault("Network Indicators", []).append(str_val)
                        elif self.string_classifier.PATH_PATTERN.match(str_val):
                            mem_strings.setdefault("File Paths", []).append(str_val)
                        elif self.string_classifier.REG_PATTERN.match(str_val):
                            mem_strings.setdefault("Registry Keys", []).append(str_val)
                        elif self.string_classifier.CMD_PATTERN.search(str_val):
                            mem_strings.setdefault("Suspicious Commands", []).append(str_val)
                        else:
                            mem_strings.setdefault("Miscellaneous", []).append(str_val)
                            
                self.report["Summary"]["Strings Extracted"] += added
                self._save_to_disk()
                return

            # ------------------------------------------------------------------
            # ------------------------------------------------------------------
            # Route: Crypto & Anti-Analysis
            # ------------------------------------------------------------------
            if ecat == "CRYPTO":
                api = payload.get("api", "")
                details = payload.get("details", {})
                if eact == "KEY_IMPORTED":
                    self.report["Cryptographic Activity"]["Keys Imported"] += 1
                    # Enrich: guess key algorithm from blob length
                    if isinstance(details, dict):
                        key_len = details.get("key_data_length", 0)
                        if key_len:
                            key_type = self._guess_key_type(key_len)
                            key_types = self.report["Cryptographic Activity"].setdefault("Key Types Observed", [])
                            if key_type not in key_types:
                                key_types.append(key_type)
                elif eact == "ENCRYPT":
                    self.report["Cryptographic Activity"]["Encryption Calls"] += 1
                elif eact == "DECRYPT":
                    self.report["Cryptographic Activity"]["Decryption Calls"] += 1
                if api and api not in self.report["Cryptographic Activity"]["Crypto APIs Used"]:
                    self.report["Cryptographic Activity"]["Crypto APIs Used"].append(api)
                    
            if ecat == "ANTI_DEBUG":
                api = payload.get('api', eact)
                if api not in self.report["Anti-Analysis Techniques"]:
                    self.report["Anti-Analysis Techniques"].append(api)

            # ------------------------------------------------------------------
            # Route: Network Activity
            # ------------------------------------------------------------------
            if ecat == "NETWORK":
                details = payload.get('details', {})
                entry = {
                    "Process ID": pid,
                    "Action":     eact,
                    "Timestamp":  ts,
                }
                
                # Protocol detection for DATA_SENT events
                if isinstance(details, dict):
                    buf_preview = details.get("buffer_preview", "")
                    if isinstance(buf_preview, str):
                        if buf_preview.startswith("\x16\x03"):
                            details["protocol"] = "TLS"
                            if len(buf_preview) >= 3:
                                tls_ver_byte = ord(buf_preview[2])
                                if tls_ver_byte == 1: details["tls_version"] = "TLS 1.0"
                                elif tls_ver_byte == 2: details["tls_version"] = "TLS 1.1"
                                elif tls_ver_byte == 3: details["tls_version"] = "TLS 1.2"
                                elif tls_ver_byte == 4: details["tls_version"] = "TLS 1.3"
                        elif buf_preview.startswith("GET ") or buf_preview.startswith("POST ") or buf_preview.startswith("HTTP/"):
                            details["protocol"] = "HTTP"
                    
                    # Remove raw unreadable bytes from final report to keep it clean
                    if "buffer_preview" in details:
                        del details["buffer_preview"]

                    # Annotate DATA_SENT with destination hostname if we tracked one from DNS
                    if eact == "DATA_SENT" and self._last_dns_host:
                        details["destination"] = self._last_dns_host
                    entry.update(details)
                else:
                    entry["Details"] = details

                self.report["Network Activity"].append(entry)
                self.report["Summary"]["Network Connections"] += 1

                # IOC: extract IP / domain
                if isinstance(details, dict):
                    ip = details.get('ip')
                    if ip and ip not in self._ioc_ips:
                        self._ioc_ips.add(ip)
                        self.report["Summary"]["Unique IPs"].append(ip)
                    domain = self._clean(details.get('hostname', ''))
                    if domain and domain not in self._ioc_domains:
                        self._ioc_domains.add(domain)
                        self.report["Summary"]["Unique Domains"].append(domain)
                        # Track the last resolved hostname to annotate subsequent DATA_SENT
                        if eact == "DNS_LOOKUP":
                            self._last_dns_host = domain

                # Network connections are always HIGH-worth for Security Alerts
                if sev in ("HIGH", "CRITICAL") or eact == "CONNECTED":
                    self._add_security_alert(ecat, eact, sev, pid, ts, payload)

                self._update_verdict()
                self._save_to_disk()
                return

            # ------------------------------------------------------------------
            # Route: File System Activity
            # ------------------------------------------------------------------
            if ecat == "FILE":
                details = payload.get('details', {})
                entry = {
                    "Process ID": pid,
                    "Action":     eact,
                    "Timestamp":  ts,
                }
                if isinstance(details, dict):
                    # Decode access flags to human-readable strings
                    if 'access' in details:
                        details = dict(details)
                        details['access'] = _decode_access_flags(details['access'])
                    entry.update(details)
                else:
                    entry["Details"] = details

                self.report["File System Activity"].append(entry)

                # Summary counters
                if eact == "WRITTEN":
                    self.report["Summary"]["Files Written"] += 1
                elif eact == "DELETED":
                    self.report["Summary"]["Files Deleted"] += 1

                # PE drop detection -> Security Alert
                if eact == "WRITTEN" and isinstance(details, dict) and details.get('is_pe'):
                    self._add_security_alert(ecat, "PE_FILE_DROPPED", "CRITICAL", pid, ts, details)
                elif sev in ("HIGH", "CRITICAL"):
                    self._add_security_alert(ecat, eact, sev, pid, ts, details)

                self._update_verdict()
                self._save_to_disk()
                return

            # ------------------------------------------------------------------
            # Route: Registry Activity
            # ------------------------------------------------------------------
            if ecat == "REGISTRY":
                details = payload.get('details', {})
                entry = {
                    "Process ID": pid,
                    "Action":     eact,
                    "Timestamp":  ts,
                }
                if isinstance(details, dict):
                    entry.update(details)
                else:
                    entry["Details"] = details

                self.report["Registry Activity"].append(entry)
                self.report["Summary"]["Registry Modifications"] += 1

                if sev in ("HIGH", "CRITICAL", "SUSPICIOUS"):
                    self._add_security_alert(ecat, eact, sev, pid, ts, details)

                self._update_verdict()
                self._save_to_disk()
                return

            # ------------------------------------------------------------------
            # Route: Process Injection / Code Injection
            # ------------------------------------------------------------------
            if ecat == "INJECTION":
                details = payload.get('details', {})
                entry = {
                    "Process ID": pid,
                    "Action":     eact,
                    "Timestamp":  ts,
                }
                if isinstance(details, dict):
                    entry.update(details)
                else:
                    entry["Details"] = details

                self.report["Process & Injection Activity"].append(entry)
                self._add_security_alert(ecat, eact, sev, pid, ts, details)
                self._update_verdict()
                self._save_to_disk()
                return

            # Also route CreateProcess / NtCreateUserProcess to Process & Injection
            if ecat == "API" and payload.get('api') in (
                "CreateProcessW", "CreateProcessA", "NtCreateUserProcess"
            ):
                details = payload.get('details', {})
                entry = {
                    "Process ID": pid,
                    "Action":     payload.get('api'),
                    "Timestamp":  ts,
                }
                if isinstance(details, dict):
                    # Sanitize decode errors before writing to Injection Activity
                    cleaned = {
                        k: (self._clean(v, fallback="[Could Not Decode]") if isinstance(v, str) else v)
                        for k, v in details.items()
                    }
                    entry.update(cleaned)
                self.report["Process & Injection Activity"].append(entry)
                self._save_to_disk()
                return

            # ------------------------------------------------------------------
            # Route: Security Alerts (YARA, high-severity catches)
            # ------------------------------------------------------------------
            if sev in ("HIGH", "CRITICAL"):
                self._add_security_alert(ecat, eact, sev, pid, ts, payload)
                self._update_verdict()

            # ------------------------------------------------------------------
            # Route: Raw Captured Data (everything else except spam)
            # ------------------------------------------------------------------
            # LdrLoadDll events are already tracked in Loaded Modules; skip duplicates.
            api_name = payload.get("api", "")
            if api_name != "LdrLoadDll" and ecat not in ("OTHER",):
                self.report["Raw Captured Data"].append({
                    "Category":  ecat,
                    "Action":    eact,
                    "PID":       pid,
                    "Timestamp": ts,
                    "Payload":   payload,
                })

            self._save_to_disk()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_url_ioc(self, text: str) -> None:
        """
        Scans a string for URLs (http/https) and registers:
        - The full URL in Memory Analysis & Strings -> URLs
        - The hostname in Summary -> Unique Domains
        This ensures IOCs embedded in shell arguments or process commands are captured
        even when the DNS hook returns a DecodeError.
        """
        import re
        url_re = re.compile(r'https?://([^/\s"\'<>]+)([^\s"\'<>]*)', re.IGNORECASE)
        for m in url_re.finditer(text):
            full_url = m.group(0)
            hostname = m.group(1).lower().rstrip('.')
            # Track full URL in strings section
            mem = self.report.setdefault("Memory Analysis & Strings", {})
            urls = mem.setdefault("URLs", [])
            if full_url not in urls:
                urls.append(full_url)
            # Track domain in summary IOC list
            if hostname and hostname not in self._ioc_domains:
                self._ioc_domains.add(hostname)
                self.report["Summary"]["Unique Domains"].append(hostname)

    def _add_security_alert(self, ecat, eact, sev, pid, ts, details):
        """Append a de-duplicated entry to the Security Alerts section."""
        detection = (
            details.get('message')
            or details.get('api')
            or details.get('hostname')
            or details.get('ip')
            or f"{ecat}::{eact}"
        ) if isinstance(details, dict) else f"{ecat}::{eact}"

        self.report["Security Alerts"].append({
            "Severity":  sev,
            "Category":  ecat,
            "Action":    eact,
            "Detection": detection,
            "Process ID": pid,
            "Timestamp": ts,
            "Details":   details if isinstance(details, dict) else {"raw": str(details)},
        })
        self.report["Summary"]["Security Alerts"] += 1

    def _update_verdict(self):
        """
        Derives a triage verdict from current IOC counts.
        MALICIOUS  -> any injection, PE drop, or C2 connection
        SUSPICIOUS -> network connections, registry writes, or security alerts
        BENIGN     -> no alerts at all
        """
        s = self.report["Summary"]
        if (self.report["Process & Injection Activity"]
                or any(e.get("Action") == "PE_FILE_DROPPED" for e in self.report["Security Alerts"])):
            s["Verdict"] = "MALICIOUS"
        elif s["Network Connections"] > 0 or s["Security Alerts"] > 0 or s["Registry Modifications"] > 0:
            s["Verdict"] = "SUSPICIOUS"
        elif self.report["Analysis Metadata"]["Total Events Captured"] > 0:
            s["Verdict"] = "BENIGN"

    def _save_to_disk(self, force=False):
        now = time.time()
        if not force:
            # Skip saving if we haven't reached the event threshold OR the time threshold
            if (self._event_count % self.SAVE_INTERVAL_EVENTS != 0) and ((now - self._last_save_time) < self.SAVE_INTERVAL_SECONDS):
                return
                
        self._last_save_time = now
        try:
            # Always ensure Executive Summary is up-to-date even mid-flight
            self.report["Executive Summary"] = self._build_summary()
            with open(self.output_path, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, cls=CustomJSONEncoder, indent=4)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public finalization API
    # ------------------------------------------------------------------

    def save_report(self, output_path=None):
        """Finalizes and saves the structured report to disk."""
        with self.lock:
            self.report["Analysis Metadata"]["Analysis End Time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._update_verdict()
            # Consolidate Network Indicators into Strings for unified viewing
            mem_strings = self.report.setdefault("Memory Analysis & Strings", {})
            if isinstance(mem_strings, dict):
                network_indicators = mem_strings.setdefault("Network Indicators", [])
                for domain in self.report["Summary"].get("Unique Domains", []):
                    if domain not in network_indicators:
                        network_indicators.append(domain)
                for ip in self.report["Summary"].get("Unique IPs", []):
                    if ip not in network_indicators:
                        network_indicators.append(ip)

            # Cleanup empty string categories before final save
            if isinstance(mem_strings, dict):
                self.report["Memory Analysis & Strings"] = {k: v for k, v in mem_strings.items() if v}
            # Executive Summary is now updated inside _save_to_disk directly
            
            if output_path:
                self.output_path = output_path
            self._save_to_disk(force=True)
            return self.output_path
            
    def _build_summary(self) -> dict:
        """
        Builds an analyst-grade Executive Summary from the captured data.
        Priority: most critical/specific IOCs appear first in Key Findings.
        DecodeError values are never surfaced here.
        """
        s = self.report.get("Summary", {})
        findings = []

        # --- Anti-Analysis ---
        anti_debug = self.report.get("Anti-Analysis Techniques", [])
        if anti_debug:
            findings.append(f"Anti-analysis evasion detected: {', '.join(anti_debug)}")

        # --- Network: Domains (most actionable IOC — always name them) ---
        domains = [d for d in s.get("Unique Domains", []) if self._clean(d)]
        ips     = [i for i in s.get("Unique IPs",     []) if self._clean(i)]
        if domains:
            findings.append(f"Contacts external domain(s): {', '.join(domains)}")
        if ips:
            findings.append(f"Contacts external IP(s): {', '.join(ips)}")

        # --- Network: TLS / Protocol context ---
        net_activity = self.report.get("Network Activity", [])
        tls_entries  = [e for e in net_activity if e.get("protocol") == "TLS"]
        http_entries = [e for e in net_activity if e.get("protocol") == "HTTP"]
        if tls_entries:
            versions = list({e.get("tls_version", "TLS") for e in tls_entries})
            dest_hosts = list({e.get("destination") for e in tls_entries if e.get("destination")})
            dest_str = f" -> {', '.join(dest_hosts)}" if dest_hosts else ""
            findings.append(f"Sends encrypted data over {', '.join(versions)}{dest_str}")
        if http_entries:
            findings.append(f"Makes cleartext HTTP requests ({len(http_entries)} total)")
        if s.get("Network Connections", 0) > 0 and not domains and not ips and not tls_entries:
            findings.append(f"Makes {s['Network Connections']} network connection(s) — destination unknown")

        # --- Cryptographic Activity ---
        crypto = self.report.get("Cryptographic Activity", {})
        if crypto.get("Decryption Calls", 0) > 0:
            key_types = crypto.get("Key Types Observed", [])
            kt_str = f" using {', '.join(key_types)}" if key_types else ""
            findings.append(
                f"Decrypts data in memory ({crypto['Decryption Calls']} calls{kt_str})"
            )
        if crypto.get("Encryption Calls", 0) > 0:
            findings.append(f"Encrypts data in memory ({crypto['Encryption Calls']} calls)")
        if crypto.get("Keys Imported", 0) > 0:
            key_types = crypto.get("Key Types Observed", [])
            kt_str = f": {', '.join(key_types)}" if key_types else ""
            findings.append(f"Imports cryptographic key(s) ({crypto['Keys Imported']} total{kt_str})")

        # --- Process Spawning ---
        scripts   = self.report.get("Executed Scripts & Commands", {})
        launches  = scripts.get("Process Launches", [])
        # Filter out entries where App Name is a decode error
        valid_launches = [
            l for l in launches
            if self._clean(l.get("App Name", ""))
            and l.get("App Name") not in self._BAD_VALUES
            and l.get("App Name") != "[Could Not Decode]"
        ]
        if valid_launches:
            names = [os.path.basename(l["App Name"]) for l in valid_launches[:3]]
            findings.append(f"Spawns child process(es): {', '.join(names)}")

        # --- Shell Executions (filtered, no DecodeError) ---
        shells = scripts.get("Shell Executions", [])
        valid_shells = [
            x for x in shells
            if self._clean(x.get("Target", ""))
            and x.get("Target") not in self._BAD_VALUES
            and x.get("Target") != "[Could Not Decode]"
        ]
        if valid_shells:
            targets = [x["Target"] for x in valid_shells[:3]]
            findings.append(f"Shell executions: {', '.join(targets)}")

        verdict = s.get("Verdict", "UNKNOWN")
        risk = "CRITICAL" if verdict == "MALICIOUS" else "HIGH" if verdict == "SUSPICIOUS" else "LOW"

        return {
            "Verdict":       verdict,
            "Risk Level":    risk,
            "Key Findings":  findings if findings else ["No significant behavioral indicators detected."],
            "Total Alerts":  s.get("Security Alerts", 0),
            "Analysis Time": self.report.get("Analysis Metadata", {}).get("Analysis End Time", "N/A"),
        }

    def close(self):
        """Legacy close method — kept for backward compatibility."""
        pass

    def get_full_path(self):
        return self.output_path
