import os
import sys
import time
import queue
import signal
import logging
import threading
import subprocess
from enum import Enum
from dataclasses import dataclass, field

from monitor import IOAlert
from config import (
    IO_THRESHOLD_MBPS,
    SUSPICIOUS_DURATION_SEC,
    ALERT_EXPIRY_SEC,
    WHITELISTED_PROCESSES,
)

# ── Logging ───────────────────────────────────────────────────────────────────
log = logging.getLogger("Detector")


# ── State machine ─────────────────────────────────────────────────────────────
class State(Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    THROTTLED = "throttled"          # rate-limited + honeypot deployed
    KILLED = "killed"
    CLEARED = "cleared"


# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class Verdict:
    """Message format from Honeypot → Detector."""
    pid: int
    is_ransomware: bool


@dataclass
class TrackedProcess:
    """Internal state for a process being monitored."""
    pid: int
    name: str
    state: State = State.NORMAL
    state_since: float = field(default_factory=time.time)
    last_alert: float = field(default_factory=time.time)
    peak_mbps: float = 0.0


# ── Detector ──────────────────────────────────────────────────────────────────
class Detector:
    def __init__(self, alert_queue: queue.Queue, verdict_queue: queue.Queue,
                 rate_limiter=None, honeypot=None):
        """
        alert_queue  — Monitor puts IOAlert objects here
        verdict_queue — Honeypot puts Verdict objects here
        rate_limiter — object with .throttle(pid) and .release(pid)
        honeypot     — object with .deploy_for_process(pid)
        """
        self.alert_queue = alert_queue
        self.verdict_queue = verdict_queue
        self.rate_limiter = rate_limiter
        self.honeypot = honeypot

        self.tracked: dict[int, TrackedProcess] = {}
        self._lock = threading.Lock()
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

        Pipeline:
          1. NORMAL → SUSPICIOUS  (first time we see high I/O)
          2. SUSPICIOUS → THROTTLED  (sustained high I/O)
             - Throttle process to 1 MB/s via cgroups
             - Deploy honeypot files
          3. THROTTLED → KILLED  (honeypot says ransomware)
             or THROTTLED → CLEARED  (honeypot says clean → release throttle)
        """
        # Ignore whitelisted processes entirely
        if self.is_whitelisted(alert.name):
            return

        # Ignore alerts below threshold
        if alert.write_mbps < IO_THRESHOLD_MBPS:
            with self._lock:
                if alert.pid in self.tracked:
                    proc = self.tracked[alert.pid]
                    if proc.state == State.SUSPICIOUS:
                        log.info(f"PID {alert.pid} ({alert.name}) I/O normalized — resetting to NORMAL")
                        proc.state = State.NORMAL
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

            if alert.write_mbps > proc.peak_mbps:
                proc.peak_mbps = alert.write_mbps

            # ── NORMAL → SUSPICIOUS ───────────────────────────────────
            if proc.state == State.NORMAL:
                proc.state = State.SUSPICIOUS
                proc.state_since = time.time()
                log.info(f"PID {alert.pid} ({alert.name}) → SUSPICIOUS "
                         f"({alert.write_mbps:.1f} MB/s)")

            # ── SUSPICIOUS → THROTTLED ────────────────────────────────
            elif proc.state == State.SUSPICIOUS:
                elapsed = time.time() - proc.state_since
                log.info(f"PID {alert.pid} suspicious for {elapsed:.0f}s "
                         f"(threshold: {SUSPICIOUS_DURATION_SEC}s)")

                if elapsed >= SUSPICIOUS_DURATION_SEC:
                    proc.state = State.THROTTLED
                    proc.state_since = time.time()
                    log.warning(f"PID {alert.pid} ({alert.name}) → THROTTLED")
                    self._escalate(proc)

            # ── Already throttled — waiting for honeypot verdict ──────
            elif proc.state == State.THROTTLED:
                log.info(f"PID {alert.pid} still throttled, waiting for honeypot verdict "
                         f"({alert.write_mbps:.1f} MB/s)...")

    def handle_verdict(self, pid: int, is_ransomware: bool):
        """
        Called when the Honeypot returns its verdict.
        KILL the process or RELEASE the throttle.
        """
        with self._lock:
            if pid not in self.tracked:
                log.warning(f"Received verdict for unknown PID {pid} — ignoring")
                return

            proc = self.tracked[pid]

            if is_ransomware:
                log.critical(f"HONEYPOT CONFIRMED RANSOMWARE — Killing PID {pid} ({proc.name})")
                self._kill_process(pid)
                proc.state = State.KILLED

            else:
                log.info(f"PID {pid} ({proc.name}) CLEARED — not ransomware. Releasing throttle.")
                if self.rate_limiter:
                    self.rate_limiter.release(pid)
                proc.state = State.CLEARED

    def check_stale_processes(self):
        """Reset processes that stopped sending alerts back to NORMAL."""
        now = time.time()
        with self._lock:
            for pid, proc in list(self.tracked.items()):
                if proc.state not in (State.NORMAL, State.KILLED, State.CLEARED):
                    if now - proc.last_alert > ALERT_EXPIRY_SEC:
                        log.info(f"PID {pid} ({proc.name}) went quiet — resetting to NORMAL")
                        if proc.state == State.THROTTLED and self.rate_limiter:
                            self.rate_limiter.release(pid)
                        proc.state = State.NORMAL
                        proc.state_since = now

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _escalate(self, proc: TrackedProcess):
        """Throttle the process AND deploy the honeypot."""
        # Step 1: Throttle via cgroups to 1 MB/s
        if self.rate_limiter:
            log.info(f"Throttling PID {proc.pid} to 1 MB/s")
            self.rate_limiter.throttle(proc.pid)
        else:
            log.warning(f"[no rate limiter] Cannot throttle PID {proc.pid} — "
                        f"process will continue at full speed without cgroups!")

        # Step 2: Deploy honeypot files
        if self.honeypot:
            log.info(f"Deploying honeypot for PID {proc.pid}")
            self.honeypot.deploy_for_process(proc.pid)
        else:
            log.warning(f"[no honeypot] Cannot verify PID {proc.pid} — "
                        f"no way to confirm or deny ransomware!")

    def _kill_process(self, pid: int):
        """Send SIGKILL to a process."""
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=False)
            else:
                os.kill(pid, signal.SIGKILL)
            log.critical(f"PID {pid} killed.")
        except ProcessLookupError:
            log.warning(f"PID {pid} already dead.")
        except PermissionError:
            log.error(f"No permission to kill PID {pid}. Run with sudo.")

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
