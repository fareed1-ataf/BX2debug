import os
import json
import threading
from datetime import datetime
from bx2debug.utils.encoders import CustomJSONEncoder


class JsonLogger:
    """
    Expert StateTracker that builds a structured analysis report in memory
    and saves it as a categorized JSON file at the end.
    """

    def __init__(self, target_path, mode="FULL_TRACE", output_path=None):
        self.target_path = target_path
        self.target_name = os.path.basename(target_path)
        self.mode = mode
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Determine output path immediately for live saving
        if output_path:
            self.output_path = output_path
        else:
            log_dir = "reports"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_path = os.path.join(log_dir, f"report_{self.target_name}_{timestamp}.json")

        self.report = {
            "Analysis Metadata": {
                "Target Name": self.target_name,
                "Target Path": os.path.abspath(target_path),
                "Analysis Start Time": self.start_time,
                "Analysis End Time": None,
                "Execution Mode": mode,
                "Total Events Captured": 0
            },
            "Process Tree": [],
            "Loaded Modules (DLLs)": [],
            "Network & API Activity": [],
            "Memory Analysis & Strings": [],
            "Security Alerts (YARA & Heuristics)": [],
            "Raw Captured Data": []
        }

        self.lock = threading.Lock()
        self.processes_map = {}  # PID -> Process Info dict for tree building
        self.last_save_time = 0

    def log(self, event):
        """
        Processes events, populates the structured report, and saves live.
        """
        with self.lock:
            self.report["Analysis Metadata"]["Total Events Captured"] += 1

            ecat = getattr(event, 'category', 'OTHER')
            eact = getattr(event, 'action', 'EVENT')
            sev = getattr(event, 'severity', 'INFO')
            pid = getattr(event, 'pid', 0)
            payload = getattr(event, 'payload', {})

            if hasattr(ecat, 'name'): ecat = ecat.name
            if hasattr(eact, 'name'): eact = eact.name
            if hasattr(sev, 'name'): sev = sev.name

            handled = False

            # 1. Process Tree Tracking
            if ecat == "PROCESS" and eact == "CREATED":
                proc_info = {
                    "Process ID": pid,
                    "Process Path": payload.get('path', 'Unknown'),
                    "Parent PID": payload.get('parent_pid', 0),
                    "Status": "Running",
                    "Child Processes": []
                }
                self.processes_map[pid] = proc_info

                parent_pid = payload.get('parent_pid', 0)
                if not payload.get('is_root') and parent_pid in self.processes_map:
                    self.processes_map[parent_pid]["Child Processes"].append(proc_info)
                else:
                    self.report["Process Tree"].append(proc_info)
                handled = True

            elif ecat == "PROCESS" and eact == "EXITED":
                if pid in self.processes_map:
                    self.processes_map[pid]["Status"] = f"Exited (Code: {payload.get('exit_code', 'N/A')})"
                handled = True

            # 2. DLLs
            elif ecat == "DLL" and eact == "LOADED":
                self.report["Loaded Modules (DLLs)"].append({
                    "Process ID": pid,
                    "DLL Path": payload.get('path', 'Unknown'),
                    "Base Address": hex(payload.get('base_address', 0)) if isinstance(payload.get('base_address'),
                                                                                      int) else str(
                        payload.get('base_address'))
                })
                handled = True

            # 3. Memory & Strings
            elif eact in ("STRING_FOUND", "NEW_STRINGS_FOUND"):
                found_strings = payload.get('strings', [])
                for s in found_strings:
                    if s not in self.report["Memory Analysis & Strings"]:
                        self.report["Memory Analysis & Strings"].append(s)
                handled = True

            # 4. Network & API Activity
            elif ecat == "NETWORK" or "api" in str(eact).lower() or "ip" in payload or "url" in payload:
                self.report["Network & API Activity"].append({
                    "Process ID": pid,
                    "Action": eact,
                    "Details": payload
                })
                handled = True

            # 5. Security Alerts
            if ecat in ("SECURITY", "API", "NETWORK") or sev in ("HIGH", "CRITICAL"):
                self.report["Security Alerts (YARA & Heuristics)"].append({
                    "Severity": sev,
                    "Detection": payload.get('message') or payload.get('api') or f"{ecat}::{eact}",
                    "Process ID": pid,
                    "Timestamp": datetime.now().strftime("%H:%M:%S"),
                    "Details": payload
                })

                if ecat in ("API", "NETWORK"):
                    self.report["Network & API Activity"].append({
                        "Category": ecat,
                        "Action": eact,
                        "PID": pid,
                        "Details": payload,
                        "Timestamp": datetime.now().strftime("%H:%M:%S")
                    })
                handled = True

            # 6. Raw Data (If not handled by specific categories or just to be safe)
            if not handled or ecat == "OTHER":
                self.report["Raw Captured Data"].append({
                    "Category": ecat,
                    "Action": eact,
                    "PID": pid,
                    "Payload": payload
                })

            # Real-Time Saving (Every event to ensure data safety)
            self._save_to_disk()

    def _save_to_disk(self):
        """Internal method to save the current state to disk."""
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, cls=CustomJSONEncoder, indent=4)
        except Exception:
            pass

    def save_report(self, output_path=None):
        """Finalizes and saves the structured report to disk."""
        with self.lock:
            self.report["Analysis Metadata"]["Analysis End Time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if output_path:
                self.output_path = output_path

            self._save_to_disk()
            return self.output_path

    def close(self):
        """Legacy close method."""
        pass

    def get_full_path(self):
        return "reports/report_" + self.target_name + "_[timestamp].json"
