import os
import time
import queue
import threading
import logging
from dataclasses import dataclass, field

from config import IO_THRESHOLD_MBPS

log = logging.getLogger("Monitor")


@dataclass
class IOAlert:
    """Alert sent to detector when process exceeds threshold."""
    pid: int
    name: str
    write_mbps: float
    timestamp: float = field(default_factory=time.time)


class Monitor:
    def __init__(self, alert_queue: queue.Queue, interval: float = 0.25,
                 threshold_mbps: float | None = None):
        self.alert_queue = alert_queue
        self.interval = interval
        self.threshold_mbps = threshold_mbps if threshold_mbps is not None else IO_THRESHOLD_MBPS
        self._running = False
        self._last_readings: dict[str, int] = {}
        self._last_poll_time: float = 0.0

    def start(self):
        self._running = True
        threading.Thread(target=self._run, daemon=True, name="MonitorLoop").start()
        log.info("Monitor started.")

    def stop(self):
        self._running = False
        log.info("Monitor stopped.")

    def _get_all_pids(self) -> list[str]:
        return [d for d in os.listdir('/proc') if d.isdigit()]

    def _get_process_name(self, pid: str) -> str:
        try:
            with open(f'/proc/{pid}/comm', 'r') as f:
                return f.read().strip()
        except (FileNotFoundError, ProcessLookupError):
            return "Unknown"

    def _read_proc_io(self, pid: str) -> dict | None:
        io_data = {}
        try:
            with open(f'/proc/{pid}/io', 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':')
                        io_data[key.strip()] = int(value.strip())
            return io_data
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            return None

    def _run(self):
        self._last_poll_time = time.time()
        # First pass: just collect baseline readings
        for pid_str in self._get_all_pids():
            data = self._read_proc_io(pid_str)
            if data:
                self._last_readings[pid_str] = data.get('write_bytes', 0)
        time.sleep(self.interval)

        while self._running:
            now = time.time()
            elapsed = now - self._last_poll_time
            self._last_poll_time = now

            if elapsed <= 0:
                elapsed = self.interval  # fallback to avoid division by zero

            current_pids = self._get_all_pids()
            new_readings: dict[str, int] = {}

            for pid_str in current_pids:
                data = self._read_proc_io(pid_str)
                if not data:
                    continue

                current_write = data.get('write_bytes', 0)

                if pid_str in self._last_readings:
                    bytes_diff = current_write - self._last_readings[pid_str]
                    # Use actual elapsed time for accurate rate calculation
                    mb_ps = bytes_diff / (1024 * 1024) / elapsed

                    # Pre-filter: only send alerts for processes ABOVE threshold
                    # This prevents queue flooding with irrelevant low-I/O alerts
                    if mb_ps >= self.threshold_mbps:
                        name = self._get_process_name(pid_str)
                        alert = IOAlert(
                            pid=int(pid_str),
                            name=name,
                            write_mbps=mb_ps
                        )
                        self.alert_queue.put(alert)
                        log.info(f"PID {pid_str} ({name}) → SUSPICIOUS ({mb_ps:.1f} MB/s)")

                new_readings[pid_str] = current_write

            self._last_readings = new_readings
            time.sleep(self.interval)


def main():
    print("Starting I/O monitor (standalone mode)...")

    alert_queue = queue.Queue()
    monitor = Monitor(alert_queue)

    def print_alerts():
        while True:
            try:
                alert = alert_queue.get(timeout=1)
                print(f"ALERT: PID {alert.pid} ({alert.name}) writing at {alert.write_mbps:.2f} MB/s")
            except queue.Empty:
                pass

    threading.Thread(target=print_alerts, daemon=True).start()
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Monitor.")
        monitor.stop()


if __name__ == "__main__":
    main()
