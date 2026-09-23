import os
import sys
import ctypes
from datetime import datetime


class ConsoleUI:
    """
    Expert-level Terminal UI using Pure Python and ANSI escape sequences.
    Implements aggressive filtering to ensure only high-signal security events are displayed.
    """

    # ANSI Colors
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"
    BLINK = "\033[5m"

    # Filtering rules — show all tactically relevant categories in the terminal.
    # STRING_FOUND is excluded because it generates too much output; it is logged to JSON only.
    ALLOWED_CATEGORIES = {
        "PROCESS", "DLL", "EXCEPTION", "SECURITY", "MEMORY",
        "NETWORK", "FILE", "REGISTRY", "INJECTION",
        "ANTI_DEBUG", "CRYPTO", "PRIVILEGE", "SCRIPT", "COM",
    }
    BLOCKED_ACTIONS = {"STRING_FOUND"}  # These go to JSON only
    BLOCKED_CATEGORIES = {"THREAD"}

    def __init__(self):
        self._enable_ansi()

    def _enable_ansi(self):
        """Forcefully enables ANSI processing on Windows cmd.exe."""
        if os.name == "nt":
            try:
                kernel32 = ctypes.windll.kernel32
                # STD_OUTPUT_HANDLE = -11
                handle = kernel32.GetStdHandle(-11)
                mode = ctypes.c_uint()
                kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                mode.value |= 0x0004
                kernel32.SetConsoleMode(handle, mode)
            except Exception:
                # If it fails, colors might just show as raw codes, but the tool will still work
                pass

    def draw_banner(self):
        banner = """
 ============================================================
 [ BX2DEBUG - BEHAVIORAL ANALYSIS TOOL ] 
 Advanced Behavioral Malware Analysis CLI v1.0
 ============================================================
        """
        # We print without formatting first to avoid encoding issues with special characters in some fonts
        # then we add colors to specific parts if needed, but keeping it simple for stability
        print(f"{self.BOLD}{self.RED}{banner}{self.RESET}")

    def print_info(self, message):
        print(f"{self.BOLD}{self.CYAN}[*]{self.RESET} {message}")

    def print_warning(self, message):
        print(f"{self.BOLD}{self.YELLOW}[!]{self.RESET} {message}")

    def print_error(self, message):
        print(f"{self.BOLD}{self.RED}[-]{self.RESET} {message}")

    def display_event(self, event):
        """
        Processes and prints events based on security analyst filtering preferences.
        """
        # Extract attributes handling both TraceEvent objects and dicts
        ecat = getattr(event, "category", "OTHER")
        eact = getattr(event, "action", "EVENT")
        sev = getattr(event, "severity", "INFO")
        pid = getattr(event, "pid", 0)
        payload = getattr(event, "payload", {})
        if not isinstance(payload, dict):
            payload = {}

        # Handle Enum objects from bx2trace
        if hasattr(ecat, "name"):
            ecat = ecat.name
        if hasattr(eact, "name"):
            eact = eact.name
        if hasattr(sev, "name"):
            sev = sev.name

        # --- Smart Filtering Logic ---
        if ecat in self.BLOCKED_CATEGORIES:
            return
        if eact in self.BLOCKED_ACTIONS:
            return
        if ecat not in self.ALLOWED_CATEGORIES:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")

        # Select Color based on Category and Severity
        color = self.WHITE
        prefix_icon = "[*]"

        if sev in ("HIGH", "CRITICAL"):
            color = self.RED + self.BOLD
            prefix_icon = "[!]"
            if sev == "CRITICAL":
                color += self.BLINK
        elif ecat == "PROCESS":
            color = self.CYAN
            prefix_icon = "[*]"
        elif ecat == "DLL":
            color = self.GRAY
            prefix_icon = "[+]"
        elif ecat == "SECURITY":
            color = self.YELLOW + self.BOLD
            prefix_icon = "[!]"
        elif ecat == "API":
            color = self.CYAN
            prefix_icon = "[~]"
        elif ecat == "NETWORK":
            color = self.YELLOW + self.BOLD
            prefix_icon = "[N]"
        elif ecat == "FILE":
            color = self.CYAN
            prefix_icon = "[F]"
        elif ecat == "REGISTRY":
            color = self.YELLOW
            prefix_icon = "[R]"
        elif ecat == "INJECTION":
            color = self.RED + self.BOLD
            prefix_icon = "[!]"
        elif ecat == "EXCEPTION":
            color = self.RED
            prefix_icon = "[-]"
        elif ecat == "ANTI_DEBUG":
            color = self.RED + self.BOLD
            prefix_icon = "[A]"
        elif ecat == "CRYPTO":
            color = self.YELLOW
            prefix_icon = "[K]"
        elif ecat == "PRIVILEGE":
            color = self.RED + self.BOLD
            prefix_icon = "[P]"
        elif ecat == "SCRIPT":
            color = self.YELLOW + self.BOLD
            prefix_icon = "[S]"
        elif ecat == "COM":
            color = self.GRAY
            prefix_icon = "[C]"

        # --- Human Readable Payload Parsing ---
        msg = ""

        # Filtering: Analysts hate terminal flooding
        # Silently swallow STRING_FOUND and THREAD events
        if eact == "STRING_FOUND" or ecat == "THREAD":
            return

        if ecat == "PROCESS":
            if eact == "CREATED":
                msg = f"Spawned: {payload.get('path', 'Unknown')} (PID: {pid})"
            elif eact == "EXITED":
                msg = f"Terminated: PID {pid} (Exit Code: {payload.get('exit_code', 'N/A')})"

        elif ecat == "DLL":
            if eact == "LOADED":
                msg = f"Loaded: {payload.get('path', 'Unknown')} @ {hex(payload.get('base_address', 0)) if isinstance(payload.get('base_address'), int) else payload.get('base_address')}"

        elif ecat == "SECURITY":
            msg = payload.get("message") or f"Alert: {eact}"
        elif ecat == "API":
            msg = f"API Called: {payload.get('api', 'Unknown')} at {payload.get('address', '0x0')}"
            if "details" in payload:
                msg += f" ({payload['details']})"
        elif ecat == "NETWORK":
            details = payload.get('details', {})
            if isinstance(details, dict):
                if 'ip' in details:
                    msg = f"Network {eact}: {details.get('ip')}:{details.get('port', '?')} ({details.get('family', 'IPv4')})"
                elif 'hostname' in details:
                    msg = f"DNS Lookup: {details.get('hostname')}"
                elif 'bytes_to_send' in details:
                    msg = f"Data Sent: {details.get('bytes_to_send')} bytes on socket {details.get('socket', '?')}"
                else:
                    msg = f"Network {eact}: {details}"
            else:
                msg = f"Network {eact}: {details}"
        elif ecat == "FILE":
            details = payload.get('details', {})
            path = details.get('path', 'Unknown') if isinstance(details, dict) else str(details)
            access = details.get('access', '') if isinstance(details, dict) else ''
            msg = f"File {eact}: {path}  [{', '.join(access) if isinstance(access, list) else access}]"
        elif ecat == "REGISTRY":
            details = payload.get('details', {})
            if isinstance(details, dict):
                msg = f"Registry {eact}: {details.get('key_path', details.get('hkey', '?'))} -> {details.get('value_name', '')}"
            else:
                msg = f"Registry {eact}: {details}"
        elif ecat == "INJECTION":
            details = payload.get('details', {})
            target = details.get('target_pid', '?') if isinstance(details, dict) else '?'
            msg = f"Injection {eact}: target PID={target}"
        elif ecat == "EXCEPTION":
            msg = f"Exception {payload.get('exception_code', 'N/A')} at {hex(payload.get('address', 0)) if isinstance(payload.get('address'), int) else payload.get('address')}"
        elif ecat == "ANTI_DEBUG":
            msg = f"Anti-Analysis: {payload.get('api', eact)}"
        elif ecat == "CRYPTO":
            msg = f"Crypto {eact}: {payload.get('api', '?')} @ PID {pid}"
        elif ecat == "PRIVILEGE":
            msg = f"Privilege Escalation: {payload.get('api', eact)}"
        elif ecat == "SCRIPT":
            details = payload.get('details', {})
            cmd = details.get('command_line', details.get('file', eact)) if isinstance(details, dict) else str(details)
            msg = f"Script Executed: {cmd}"
        elif ecat == "COM":
            details = payload.get('details', {})
            clsid = details.get('clsid', '?') if isinstance(details, dict) else str(details)
            msg = f"COM Activated: {clsid}"

        if not msg:
            msg = getattr(event, "message", "")
            if not msg:
                msg = f"{ecat}::{eact}"

        prefix = f"{self.GRAY}[{timestamp}]{self.RESET} {color}{prefix_icon} [{ecat:^9}]{self.RESET}"
        print(f"{prefix} {msg}")

    def print_summary(self, stats):
        print(f"\n{self.BOLD}{self.CYAN}{'=' * 60}{self.RESET}")
        print(f"{self.BOLD}{self.WHITE}   ANALYSIS SUMMARY{self.RESET}")
        print(f"{self.BOLD}{self.CYAN}{'=' * 60}{self.RESET}")
        for label, value in stats.items():
            print(
                f"{self.WHITE} {label:.<35}: {self.BOLD}{self.GREEN}{value}{self.RESET}"
            )
        print(f"{self.BOLD}{self.CYAN}{'=' * 60}{self.RESET}")
