import queue
import time
from bx2trace.core.debug_thread import DebugThread
from bx2trace.core.memory_scanner import MemoryScannerThread
from bx2trace.core.models import TraceMode


class MalwareRunner:
    """
    Expert Wrapper for the bx2trace library components.
    Orchestrates the DebugThread and MemoryScannerThread.
    """

    def __init__(self, target_path, cmd_args="", yara_rules=None, mode=TraceMode.FULL_TRACE):
        self.target_path = target_path
        self.cmd_args = cmd_args
        self.yara_rules = yara_rules
        self.mode = mode

        # Central event queue shared by all threads
        self.event_queue = queue.Queue()

        self.debug_thread = None
        self.scanner_thread = None

    def start(self):
        """Initializes and launches the analysis threads."""
        # 1. Setup Debugger
        self.debug_thread = DebugThread(
            exe_path=self.target_path,
            cmd_args=self.cmd_args,
            mode=self.mode,
            raw_event_queue=self.event_queue
        )
        self.debug_thread.start()

        # Wait for the debugger to initialize properly
        if not self.debug_thread.started_ok.wait(timeout=10):
            raise RuntimeWarning("Debugger thread failed to signal 'started_ok' within timeout.")

        # 2. Setup Scanner
        # The scanner needs access to the current tracked process handles
        self.scanner_thread = MemoryScannerThread(
            get_tracked_handles=lambda: {p.pid: p.handle for p in self.debug_thread.tracked.values()},
            event_queue=self.event_queue,
            interval=1.5,
            yara_rules_path=self.yara_rules
        )
        self.scanner_thread.start()

    def stop(self):
        """Cleanly requests all threads to stop."""
        if self.scanner_thread:
            self.scanner_thread.request_stop()
        if self.debug_thread:
            self.debug_thread.request_stop()

    def join(self, timeout=5):
        """Waits for threads to finish."""
        if self.scanner_thread:
            self.scanner_thread.join(timeout=timeout)
        if self.debug_thread:
            self.debug_thread.join(timeout=timeout)

    @property
    def is_alive(self):
        """Returns True if the analysis is still active."""
        return (self.debug_thread and self.debug_thread.is_alive()) or \
            (self.scanner_thread and self.scanner_thread.is_alive())
