"""
detector.py — The Brain of the Ransomware Detection System

Receives I/O alerts from the Monitor, tracks process states,
and decides when to throttle, investigate, kill, or clear.

State machine:
    NORMAL → SUSPICIOUS → UNDER_INVESTIGATION → KILLED
                                    └──────────→ CLEARED
"""

import os
import sys
import time
import queue
import signal
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field

from config import (
    IO_THRESHOLD_MBPS,
    SUSPICIOUS_DURATION_SEC,
    ALERT_EXPIRY_SEC,
    WHITELISTED_PROCESSES,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Detector] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("Detector")

# ── State machine ─────────────────────────────────────────────────────────────
class State(Enum):
    NORMAL             = "normal"
    SUSPICIOUS         = "suspicious"
    UNDER_INVESTIGATION= "under_investigation"
    KILLED             = "killed"
    CLEARED            = "cleared"

# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class IOAlert:
    """Message format from Monitor → Detector."""
    pid:        int
    name:       str
    write_mbps: float
    timestamp:  float = field(default_factory=time.time)

@dataclass
class Verdict:
    """Message format from Honeypot → Detector."""
    pid:          int
    is_ransomware: bool

@dataclass
class TrackedProcess:
    """Internal state for a process being monitored."""
    pid:          int
    name:         str
    state:        State    = State.NORMAL
    state_since:  float    = field(default_factory=time.time)
    last_alert:   float    = field(default_factory=time.time)

# ── Detector ──────────────────────────────────────────────────────────────────
class Detector:
    def __init__(self, alert_queue: queue.Queue, verdict_queue: queue.Queue,
                 rate_limiter=None, honeypot=None):
        """
        alert_queue   — Monitor puts IOAlert objects here
        verdict_queue — Honeypot puts Verdict objects here
        rate_limiter  — object with .throttle(pid) and .release(pid)
        honeypot      — object with .deploy_for_process(pid)
        """
        self.alert_queue   = alert_queue
        self.verdict_queue = verdict_queue
        self.rate_limiter  = rate_limiter
        self.honeypot      = honeypot

        self.tracked: dict[int, TrackedProcess] = {}
        self._lock    = threading.Lock()
        self._running = False

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        """Start the detector loop in a background thread."""
        self._running = True
        threading.Thread(target=self._run, daemon=True, name="DetectorLoop").start()
        log.info("Detector started.")

    def stop(self):
        self._running = False
        log.info("Detector stopped.")

    # ── Core logic ────────────────────────────────────────────────────────────

    def is_whitelisted(self, process_name: str) -> bool:
        """Return True if this process is allowed to do heavy I/O."""
        name = process_name.lower()
        return any(name == w.lower() or name.startswith(w.lower())
                   for w in WHITELISTED_PROCESSES)

    def handle_alert(self, alert: IOAlert):
        """
        Called every time the Monitor reports a high-I/O process.
        Manages state transitions: NORMAL → SUSPICIOUS → UNDER_INVESTIGATION
        """
        # Ignore whitelisted processes entirely
        if self.is_whitelisted(alert.name):
            return

        # Ignore alerts below threshold
        if alert.write_mbps < IO_THRESHOLD_MBPS:
            # If we were tracking this process, it calmed down — reset it
            with self._lock:
                if alert.pid in self.tracked:
                    proc = self.tracked[alert.pid]
                    if proc.state == State.SUSPICIOUS:
                        log.info(f"PID {alert.pid} ({alert.name}) I/O normalized — resetting to NORMAL")
                        proc.state      = State.NORMAL
                        proc.state_since = time.time()
            return

        with self._lock:
            # First time seeing this process
            if alert.pid not in self.tracked:
                self.tracked[alert.pid] = TrackedProcess(pid=alert.pid, name=alert.name)
                log.info(f"New suspicious process: PID {alert.pid} ({alert.name}) "
                         f"writing at {alert.write_mbps:.1f} MB/s")

            proc = self.tracked[alert.pid]
            proc.last_alert = time.time()

            # ── NORMAL → SUSPICIOUS ───────────────────────────────────────
            if proc.state == State.NORMAL:
                proc.state       = State.SUSPICIOUS
                proc.state_since = time.time()
                log.info(f"PID {alert.pid} ({alert.name}) → SUSPICIOUS")

            # ── SUSPICIOUS → UNDER_INVESTIGATION ─────────────────────────
            elif proc.state == State.SUSPICIOUS:
                elapsed = time.time() - proc.state_since
                log.info(f"PID {alert.pid} suspicious for {elapsed:.0f}s "
                         f"(threshold: {SUSPICIOUS_DURATION_SEC}s)")

                if elapsed >= SUSPICIOUS_DURATION_SEC:
                    proc.state       = State.UNDER_INVESTIGATION
                    proc.state_since = time.time()
                    log.warning(f"PID {alert.pid} ({alert.name}) → UNDER_INVESTIGATION")
                    self._escalate(proc)

            # ── Already under investigation — just wait for verdict ────────
            elif proc.state == State.UNDER_INVESTIGATION:
                log.info(f"PID {alert.pid} still under investigation...")

    def handle_verdict(self, pid: int, is_ransomware: bool):
        """
        Called when the Honeypot returns its verdict.
        Kills the process or releases it.
        """
        with self._lock:
            if pid not in self.tracked:
                log.warning(f"Received verdict for unknown PID {pid} — ignoring")
                return

            proc = self.tracked[pid]

            if is_ransomware:
                log.critical(f"RANSOMWARE DETECTED — Killing PID {pid} ({proc.name})")
                self._kill_process(pid)
                proc.state = State.KILLED

            else:
                log.info(f"PID {pid} ({proc.name}) cleared — not ransomware")
                if self.rate_limiter:
                    self.rate_limiter.release(pid)
                proc.state = State.CLEARED

    def check_stale_processes(self):
        """
        Reset processes that stopped sending alerts back to NORMAL.
        Call this periodically.
        """
        now = time.time()
        with self._lock:
            for pid, proc in list(self.tracked.items()):
                if proc.state not in (State.NORMAL, State.KILLED, State.CLEARED):
                    if now - proc.last_alert > ALERT_EXPIRY_SEC:
                        log.info(f"PID {pid} ({proc.name}) went quiet — resetting to NORMAL")
                        proc.state       = State.NORMAL
                        proc.state_since = now

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _escalate(self, proc: TrackedProcess):
        """Throttle the process and deploy the honeypot."""
        if self.rate_limiter:
            log.info(f"Throttling PID {proc.pid}")
            self.rate_limiter.throttle(proc.pid)
        else:
            log.info(f"[no rate limiter] Would throttle PID {proc.pid}")

        if self.honeypot:
            log.info(f"Deploying honeypot for PID {proc.pid}")
            self.honeypot.deploy_for_process(proc.pid)
        else:
            log.info(f"[no honeypot] Would deploy honeypot for PID {proc.pid}")

    def _kill_process(self, pid: int):
        """Send SIGKILL to a process. Cross-platform safe."""
        try:
            if sys.platform == "win32":
                os.system(f"taskkill /F /PID {pid}")
            else:
                os.kill(pid, signal.SIGKILL)
            log.critical(f"PID {pid} killed.")
        except ProcessLookupError:
            log.warning(f"PID {pid} already dead.")
        except PermissionError:
            log.error(f"No permission to kill PID {pid}.")

    def _run(self):
        """Main detector loop — reads from both queues."""
        while self._running:
            # Check for new alerts
            try:
                alert = self.alert_queue.get(timeout=0.5)
                if isinstance(alert, IOAlert):
                    self.handle_alert(alert)
            except queue.Empty:
                pass

            # Check for verdicts from honeypot
            try:
                verdict = self.verdict_queue.get_nowait()
                if isinstance(verdict, Verdict):
                    self.handle_verdict(verdict.pid, verdict.is_ransomware)
            except queue.Empty:
                pass

            # Cleanup stale processes
            self.check_stale_processes()


# ── Fake stubs for standalone testing ─────────────────────────────────────────
class FakeRateLimiter:
    def throttle(self, pid): log.info(f"[FakeRateLimiter] Throttling PID {pid}")
    def release(self, pid):  log.info(f"[FakeRateLimiter] Releasing PID {pid}")

class FakeHoneypot:
    def __init__(self, verdict_queue, answer_after=3.0, is_ransomware=True):
        self.verdict_queue = verdict_queue
        self.answer_after  = answer_after
        self.is_ransomware = is_ransomware

    def deploy_for_process(self, pid):
        log.info(f"[FakeHoneypot] Watching PID {pid}, will respond in {self.answer_after}s")
        def _respond():
            time.sleep(self.answer_after)
            self.verdict_queue.put(Verdict(pid=pid, is_ransomware=self.is_ransomware))
        threading.Thread(target=_respond, daemon=True).start()


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("  DETECTOR — Standalone Test")
    print("="*55 + "\n")

    alert_queue   = queue.Queue()
    verdict_queue = queue.Queue()

    rate_limiter = FakeRateLimiter()
    honeypot     = FakeHoneypot(verdict_queue, answer_after=3.0, is_ransomware=True)

    detector = Detector(alert_queue, verdict_queue, rate_limiter, honeypot)
    detector.start()

    FAKE_PID  = 9999
    FAKE_NAME = "evil_encrypt"

    print(f"Sending alerts for PID {FAKE_PID} ({FAKE_NAME}) at 120 MB/s...\n")

    # Send 10 alerts over 10 seconds — should trigger full state machine
    for i in range(10):
        alert_queue.put(IOAlert(pid=FAKE_PID, name=FAKE_NAME, write_mbps=120.0))
        time.sleep(1)

    # Give the honeypot time to respond + detector to process verdict
    print("\nWaiting for honeypot verdict...\n")
    time.sleep(5)

    detector.stop()
    print("\n" + "="*55)
    print("  Test complete.")
    print("="*55 + "\n")
