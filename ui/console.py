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

    # Filtering rules
    ALLOWED_CATEGORIES = {"PROCESS", "DLL", "EXCEPTION", "SECURITY", "MEMORY"}
    BLOCKED_ACTIONS = {"STRING_FOUND"}  # These go to JSON only
    BLOCKED_CATEGORIES = {"THREAD"}

    def __init__(self):
        self._enable_ansi()

    def _enable_ansi(self):
        """Forcefully enables ANSI processing on Windows cmd.exe."""
        if os.name == 'nt':
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
        ecat = getattr(event, 'category', 'OTHER')
        eact = getattr(event, 'action', 'EVENT')
        sev = getattr(event, 'severity', 'INFO')
        pid = getattr(event, 'pid', 0)
        payload = getattr(event, 'payload', {})

        # Handle Enum objects from bx2trace
        if hasattr(ecat, 'name'): ecat = ecat.name
        if hasattr(eact, 'name'): eact = eact.name
        if hasattr(sev, 'name'): sev = sev.name

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
            if sev == "CRITICAL": color += self.BLINK
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
        elif ecat == "EXCEPTION":
            color = self.RED
            prefix_icon = "[-]"

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
            msg = payload.get('message') or f"Alert: {eact}"
        elif ecat == "API":
            msg = f"API Called: {payload.get('api', 'Unknown')} at {payload.get('address', '0x0')}"
            if 'details' in payload:
                msg += f" ({payload['details']})"
        elif ecat == "NETWORK":
            msg = f"Network Activity: {eact} -> {payload.get('details', payload)}"
        elif ecat == "EXCEPTION":
            msg = f"Exception {payload.get('exception_code', 'N/A')} at {hex(payload.get('address', 0)) if isinstance(payload.get('address'), int) else payload.get('address')}"

        if not msg:
            msg = getattr(event, 'message', '')
            if not msg:
                msg = f"{ecat}::{eact}"

        prefix = f"{self.GRAY}[{timestamp}]{self.RESET} {color}{prefix_icon} [{ecat:^9}]{self.RESET}"
        print(f"{prefix} {msg}")

    def print_summary(self, stats):
        print(f"\n{self.BOLD}{self.CYAN}{'=' * 60}{self.RESET}")
        print(f"{self.BOLD}{self.WHITE}   ANALYSIS SUMMARY{self.RESET}")
        print(f"{self.BOLD}{self.CYAN}{'=' * 60}{self.RESET}")
        for label, value in stats.items():
            print(f"{self.WHITE} {label:.<35}: {self.BOLD}{self.GREEN}{value}{self.RESET}")
        print(f"{self.BOLD}{self.CYAN}{'=' * 60}{self.RESET}")
