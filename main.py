#!/usr/bin/env python3
"""
Ransomware Detection System - Main Entry Point

This system monitors process I/O activity and detects potential ransomware
by watching for suspicious write patterns. When detected, it:
1. Throttles the suspicious process to 1 MB/s using cgroups
2. Deploys honeypot files in user directories to verify ransomware behavior
3. Kills confirmed ransomware processes (honeypot files modified)
4. Releases throttle for cleared processes (honeypot files untouched)

Usage:
  sudo python3 main.py

Note: Requires root/sudo for cgroup operations and process termination.
"""

import sys
import time
import queue
import logging
import argparse

from config import IO_THRESHOLD_MBPS, SUSPICIOUS_DURATION_SEC, HONEYPOT_WATCH_SEC
from monitor import Monitor
from detector import Detector
from honeypot import Honeypot

# Try to import rate limiter (requires Linux + cgroups v2)
try:
    import ratelimiter as rate_limiter_module
    RATE_LIMITER_AVAILABLE = True
except ImportError:
    RATE_LIMITER_AVAILABLE = False
    print("[Warning] Rate limiter not available - running in detection-only mode")


# ── Logging Setup ─────────────────────────────────────────────────────────────
def setup_logging(verbose: bool = False):
    """Configure logging for all components."""
    level = logging.DEBUG if verbose else logging.INFO

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(name)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(level)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(console)

    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logging.getLogger("Main")


# ── Platform Check ────────────────────────────────────────────────────────────
def check_platform():
    """Verify the system is Linux (required for /proc filesystem)."""
    if sys.platform != "linux":
        print(f"Error: This system requires Linux. Detected: {sys.platform}")
        print("The monitor uses /proc filesystem which is Linux-specific.")
        sys.exit(1)

    import os
    if not os.path.isdir("/proc"):
        print("Error: /proc filesystem not found.")
        print("This is required for process monitoring.")
        sys.exit(1)


def check_permissions():
    """Check if running with sufficient privileges."""
    import os
    if os.geteuid() != 0:
        print("\n[Warning] Not running as root.")
        print(" - Process monitoring will work")
        print(" - Rate limiting requires root (cgroups)")
        print(" - Killing processes requires root or same user\n")
        return False
    return True


# ── Main Function ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py              # Start with default settings
  sudo python3 main.py --verbose    # Enable debug logging
  sudo python3 main.py --no-throttle  # Disable rate limiting
"""
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--no-throttle",
        action="store_true",
        help="Disable rate limiting (detection-only mode)"
    )
    parser.add_argument(
        "--no-honeypot",
        action="store_true",
        help="Disable honeypot verification (alert-only mode)"
    )

    args = parser.parse_args()

    # Setup
    log = setup_logging(args.verbose)
    check_platform()
    has_root = check_permissions()

    # Shared queues for inter-component communication
    alert_queue: queue.Queue = queue.Queue()
    verdict_queue: queue.Queue = queue.Queue()

    # Initialize components
    log.info("=" * 60)
    log.info("Ransomware Detection System - Starting")
    log.info("=" * 60)

    # Monitor: watches /proc for high I/O
    monitor = Monitor(alert_queue, interval=1.0)
    log.info("Monitor initialized")

    # Rate limiter: throttles suspicious processes to 1 MB/s via cgroups
    rate_limiter = None
    if not args.no_throttle and RATE_LIMITER_AVAILABLE and has_root:
        rate_limiter = rate_limiter_module
        log.info("Rate limiter initialized (cgroups v2)")
    else:
        log.info("Rate limiter disabled or unavailable")

    # Honeypot: creates decoy files in user directories to verify ransomware
    honeypot = None
    if not args.no_honeypot:
        honeypot = Honeypot(verdict_queue, watch_duration=HONEYPOT_WATCH_SEC)
        log.info("Honeypot initialized")
    else:
        log.info("Honeypot disabled")

    # Detector: state machine that coordinates everything
    detector = Detector(
        alert_queue=alert_queue,
        verdict_queue=verdict_queue,
        rate_limiter=rate_limiter,
        honeypot=honeypot
    )
    log.info("Detector initialized")

    # Print configuration
    log.info("-" * 40)
    log.info(f"I/O Threshold: {IO_THRESHOLD_MBPS} MB/s")
    log.info(f"Suspicious Duration: {SUSPICIOUS_DURATION_SEC} seconds")
    log.info(f"Honeypot Watch: {HONEYPOT_WATCH_SEC} seconds")
    log.info(f"Rate Limiting: {'enabled' if rate_limiter else 'disabled'}")
    log.info(f"Honeypot: {'enabled' if honeypot else 'disabled'}")
    log.info("-" * 40)

    # Start components
    try:
        monitor.start()
        detector.start()
        log.info("All components started. Press Ctrl+C to stop.")

        # Main loop - just keep running
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        log.info("\nShutting down...")
        monitor.stop()
        detector.stop()

        # Cleanup rate limiter if it was used
        if rate_limiter:
            try:
                rate_limiter.cleanup()
                log.info("Rate limiter cleanup complete")
            except Exception as e:
                log.error(f"Rate limiter cleanup failed: {e}")

        log.info("Shutdown complete. Goodbye.")

    except Exception as e:
        log.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
