import os
import sys
import argparse
import signal
import queue
import time
from datetime import datetime

# Adjusting path to allow module-style imports within the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bx2debug.ui.console import ConsoleUI
from bx2debug.storage.json_logger import JsonLogger
from bx2debug.engine.runner import MalwareRunner
from bx2trace.core.models import TraceMode


class BX2debugApp:
    """
    Main Application Controller for BX2debug.
    Handles CLI arguments, signal management, and the main event orchestration loop.
    """

    def __init__(self, args):
        self.args = args
        self.ui = ConsoleUI()
        self.logger = None
        self.runner = None

        self.shutting_down = False
        self.stats = {
            "Total Events": 0,
            "Security Alerts": 0,
            "Strings Extracted": 0,
            "DLLs Loaded": 0,
            "Processes Tracked": 0
        }

    def _signal_handler(self, sig, frame):
        """Expert Signal Handler for graceful shutdown."""
        if self.shutting_down:
            return  # Ignore subsequent Ctrl+C

        self.shutting_down = True
        print("\n")
        self.ui.print_warning("SIGINT received. Requesting graceful shutdown of all engines...")

        if self.runner:
            self.runner.stop()

    def run(self):
        self.ui.draw_banner()

        # 1. Initialize Logger (StateTracker)
        self.logger = JsonLogger(self.args.target, mode="FULL_TRACE", output_path=self.args.out)
        self.ui.print_info(f"Target Acquired: {self.args.target}")
        self.ui.print_info(f"Live Report: {self.logger.output_path}")

        # 2. Setup Runner
        mode = TraceMode.FULL_TRACE
        self.runner = MalwareRunner(
            self.args.target,
            cmd_args=self.args.args,
            yara_rules=self.args.yara,
            mode=mode
        )

        # 3. Register Signal Handler
        signal.signal(signal.SIGINT, self._signal_handler)

        # 4. Start Engines
        try:
            self.runner.start()
            self.ui.print_info("Engines launched. Monitoring behavioral activity...")
        except Exception as e:
            self.ui.print_error(f"Startup Failure: {e}")
            return

        # 5. Main Orchestration Loop
        try:
            while self.runner.is_alive or not self.runner.event_queue.empty():
                try:
                    # Non-blocking get with short timeout to keep loop responsive
                    event = self.runner.event_queue.get(timeout=0.2)
                    self._process_event(event)
                except queue.Empty:
                    if self.shutting_down and not self.runner.is_alive:
                        break
                    continue
                except Exception:
                    # Internal processing error, shouldn't stop the analysis
                    pass
        finally:
            self._cleanup()

    def _process_event(self, event):
        """Internal processing of a single event."""
        # 1. Update Stats
        self.stats["Total Events"] += 1

        ecat = getattr(event, 'category', 'OTHER')
        eact = getattr(event, 'action', 'EVENT')
        sev = getattr(event, 'severity', 'INFO')

        if hasattr(ecat, 'name'): ecat = ecat.name
        if hasattr(eact, 'name'): eact = eact.name
        if hasattr(sev, 'name'): sev = sev.name

        if ecat == "SECURITY" or sev in ("HIGH", "CRITICAL"):
            self.stats["Security Alerts"] += 1
        elif ecat == "DLL" and eact == "LOADED":
            self.stats["DLLs Loaded"] += 1
        elif ecat == "PROCESS" and eact == "CREATED":
            self.stats["Processes Tracked"] += 1
        elif eact == "STRING_FOUND":
            payload = getattr(event, 'payload', {})
            count = len(payload.get('strings', []))
            self.stats["Strings Extracted"] += count

        # 2. Update In-Memory Report (EVERYTHING)
        if self.logger:
            self.logger.log(event)

        # 3. Display to UI (FILTERED)
        self.ui.display_event(event)

    def _cleanup(self):
        """Final cleanup and summary."""
        self.ui.print_info("Analysis session terminating. Joining threads...")
        if self.runner:
            self.runner.join(timeout=3)

        if self.logger:
            report_path = self.logger.save_report(self.args.out)
            if report_path:
                self.ui.print_info(f"Structured Report Saved: {report_path}")

        self.ui.print_summary(self.stats)
        self.ui.print_info("Goodbye.")


def main():
    # Force ANSI colors on Windows legacy CMD
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    if len(sys.argv) == 1:
        ui = ConsoleUI()
        ui.draw_banner()
        help_text = f"""
{ui.BOLD}{ui.WHITE}USAGE:{ui.RESET}
  bx2debug -t <target> [options]

{ui.BOLD}{ui.WHITE}OPTIONS:{ui.RESET}
  {ui.CYAN}-t, --target{ui.RESET}    Path to the executable to analyze ({ui.RED}Required{ui.RESET})
  {ui.CYAN}-a, --args{ui.RESET}      Command line arguments for the target executable
  {ui.CYAN}-y, --yara{ui.RESET}      Path to YARA rules file or directory
  {ui.CYAN}-o, --out{ui.RESET}       Custom path to save the structured JSON report
  {ui.CYAN}-h, --help{ui.RESET}      Show this help menu

{ui.BOLD}{ui.WHITE}EXAMPLES:{ui.RESET}
  bx2debug -t malware.exe
  bx2debug -t cmd.exe -a "/c whoami"
  bx2debug -t suspicious.exe -y ./rules.yar -o final_report.json

{ui.GRAY}BX2debug uses bx2trace engine to monitor behavior and live memory.{ui.RESET}
        """
        print(help_text)
        sys.exit(0)

    parser = argparse.ArgumentParser(description="BX2debug - Advanced Behavioral Malware Analysis CLI", add_help=False)
    parser.add_argument("-t", "--target", help="Path to the executable to analyze", required=True)
    parser.add_argument("-a", "--args", help="Command line arguments for the target", default="")
    parser.add_argument("-y", "--yara", help="Path to YARA rules file/directory", default=None)
    parser.add_argument("-o", "--out", help="Custom path to save the JSON report", default=None)
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target file not found: {args.target}")
        sys.exit(1)

    app = BX2debugApp(args)
    app.run()


if __name__ == "__main__":
    main()
