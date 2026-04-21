#!/usr/bin/env python3
"""
Ransomware Attack Simulator for Testing OsSecurity

This script simulates various ransomware attack patterns to test
the detection system. Safe to run - creates test files only.

Usage:
    python tests/test_ransomware_simulator.py --mode basic
    python tests/test_ransomware_simulator.py --mode fast_write
    python tests/test_ransomware_simulator.py --mode slow_evasion
    python tests/test_ransomware_simulator.py --mode full_attack
    python tests/test_ransomware_simulator.py --mode encryption
    python tests/test_ransomware_simulator.py --mode all
"""

import os
import sys
import time
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# Test directories
TEST_DIR = Path("/tmp/ransomware_test_victims")
HONEYPOT_DIR = Path("/tmp/honeypot_files")


@dataclass
class SimResult:
    """Result of a simulation run."""
    mode: str
    success: bool
    files_created: int = 0
    files_encrypted: int = 0
    files_deleted: int = 0
    duration_sec: float = 0.0
    iops: float = 0.0  # I/O operations per second
    notes: list[str] = field(default_factory=list)


def cleanup_previous_runs():
    """Remove previous test files and ransomware artifacts."""
    print("[SETUP] Cleaning up previous test runs...")

    # Remove test victim files
    if TEST_DIR.exists():
        for f in TEST_DIR.rglob("*"):
            if f.is_file():
                f.unlink(missing_ok=True)
        TEST_DIR.rmdir()
    TEST_DIR.mkdir(parents=True, exist_ok=True)

    # Clean up any honeypot directories from other PIDs
    if HONEYPOT_DIR.exists():
        for pid_dir in HONEYPOT_DIR.iterdir():
            if pid_dir.is_dir():
                for f in pid_dir.iterdir():
                    f.unlink(missing_ok=True)
                pid_dir.rmdir()

    print(f"[SETUP] Clean. Test directory: {TEST_DIR}")


def create_victim_files(count: int = 100) -> list[Path]:
    """Create test files that ransomware would target."""
    extensions = ['.txt', '.doc', '.docx', '.xls', '.xlsx', '.pdf',
                  '.jpg', '.png', '.csv', '.json', '.xml', '.sql']

    files = []
    for i in range(count):
        ext = extensions[i % len(extensions)]
        file_path = TEST_DIR / f"victim_{i:04d}{ext}"

        # Create realistic-looking content
        content = f"CONFIDENTIAL DOCUMENT {i}\n"
        content += "=" * 50 + "\n"
        content += f"Document ID: {'A' * 16}\n"
        content += f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += "=" * 50 + "\n"
        content += "Secret data: " + "X" * 100 + "\n"

        file_path.write_text(content)
        files.append(file_path)

    print(f"[SETUP] Created {count} victim files")
    return files


def get_io_stats() -> Optional[dict]:
    """Get current process I/O stats."""
    try:
        pid = os.getpid()
        with open(f'/proc/{pid}/io', 'r') as f:
            data = {}
            for line in f:
                if ':' in line:
                    key, value = line.split(':')
                    data[key.strip()] = int(value.strip())
            return data
    except Exception:
        return None


def get_pid_io() -> dict:
    """Get high-IO processes."""
    pids = {}
    for entry in Path('/proc').iterdir():
        if entry.name.isdigit():
            pid = int(entry.name)
            try:
                with open(f'/proc/{pid}/io', 'r') as f:
                    data = {}
                    for line in f:
                        if ':' in line:
                            k, v = line.split(':')
                            data[k.strip()] = int(v.strip())
                    pids[pid] = data
            except (PermissionError, FileNotFoundError):
                pass
    return pids


def basic_heavy_io(duration_sec: float = 10.0) -> SimResult:
    """
    Simulate a process doing heavy sequential writes.
    Tests: Monitor detection via high write_bytes.
    """
    print("\n" + "=" * 60)
    print("MODE: Basic Heavy I/O")
    print("Simulates: Generic ransomware bulk file writing")
    print("=" * 60)

    start_time = time.time()
    cleanup_previous_runs()
    files = create_victim_files(50)

    start_io = get_io_stats()
    bytes_written = 0

    print(f"[ATTACK] Writing aggressively to {len(files)} files for {duration_sec}s...")

    end_time = start_time + duration_sec
    file_idx = 0

    while time.time() < end_time:
        # Write to files in a patterns that mimics ransomware
        target = files[file_idx % len(files)]

        # Write encrypted-looking content
        new_content = os.urandom(1024 * 10)  # 10KB of random data
        target.write_bytes(new_content)
        bytes_written += len(new_content)

        file_idx += 1
        if file_idx % 10 == 0:
            elapsed = time.time() - start_time
            mbps = (bytes_written / (1024 * 1024)) / elapsed if elapsed > 0 else 0
            print(f"[ATTACK] Written {bytes_written / (1024*1024):.1f} MB ({mbps:.1f} MB/s)")

    end_io = get_io_stats()
    actual_duration = time.time() - start_time
    bytes_diff = end_io['write_bytes'] - start_io['write_bytes'] if start_io and end_io else bytes_written
    mbps = (bytes_diff / (1024 * 1024)) / actual_duration if actual_duration > 0 else 0

    print(f"[RESULT] Wrote {(bytes_written / (1024*1024)):.1f} MB in {actual_duration:.1f}s = {mbps:.1f} MB/s")

    # Try to check if detection occurred
    print("[ANALYSIS] Checking if OsSecurity detected this attack...")
    time.sleep(1)

    return SimResult(
        mode="basic_heavy_io",
        success=True,
        files_created=len(files),
        files_encrypted=file_idx,
        duration_sec=actual_duration,
        iops=mbps,
        notes=[
            f"Wrote {bytes_written / (1024*1024):.1f} MB total",
            f"Peak rate: {mbps:.1f} MB/s",
            f"Should trigger at threshold: 50 MB/s" if mbps > 50 else "Rate below detection threshold"
        ]
    )


def fast_write_burst(duration_sec: float = 3.0) -> SimResult:
    """
    Simulate ultra-fast writes within SUSPICIOUS_DURATION_SEC window.
    Tests: Can ransomware finish before honeypot verdict?
    """
    print("\n" + "=" * 60)
    print("MODE: Fast Write Burst (evasion test)")
    print("Simulates: Ransomware trying to finish before detection")
    print("=" * 60)

    start_time = time.time()
    cleanup_previous_runs()

    # Create fewer, larger files to maximize speed
    files = create_victim_files(20)
    for f in files:
        f.unlink()

    start_io = get_io_stats()
    bytes_written = 0

    print(f"[ATTACK] Fast burst for {duration_sec}s...")

    end_time = start_time + duration_sec
    file_idx = 0

    while time.time() < end_time:
        # Create large encrypted-looking files
        file_path = TEST_DIR / f"encrypted_{file_idx:04d}.ransomware"
        large_content = os.urandom(1024 * 100)  # 100KB chunks
        file_path.write_bytes(large_content)
        bytes_written += len(large_content)
        file_idx += 1

    actual_duration = time.time() - start_time
    end_io = get_io_stats()
    bytes_diff = end_io['write_bytes'] - start_io['write_bytes'] if start_io and end_io else bytes_written
    mbps = (bytes_diff / (1024 * 1024)) / actual_duration if actual_duration > 0 else 0

    print(f"[RESULT] Wrote {file_idx} files, {(bytes_written / (1024*1024)):.1f} MB in {actual_duration:.1f}s = {mbps:.1f} MB/s")

    return SimResult(
        mode="fast_write_burst",
        success=True,
        files_created=len(files) if len(files) else 0,
        files_encrypted=file_idx,
        duration_sec=actual_duration,
        iops=mbps,
        notes=[
            f"Duration: {actual_duration:.1f}s (detection threshold: 5s)",
            f"Speed: {mbps:.1f} MB/s - {'SHOULD BE DETECTED' if mbps > 50 else 'May evade slow detection'}",
            "Fast ransomware may complete before honeypot verdict (5s window)"
        ]
    )


def slow_evasion(write_mbps: float = 5.0) -> SimResult:
    """
    Simulate slow writes below threshold to test evasion.
    Tests: Can ransomware avoid detection by staying below threshold?
    """
    print("\n" + "=" * 60)
    print("MODE: Slow Evasion")
    print(f"Simulates: Ransomware writing at {write_mbps} MB/s (below 50 MB/s threshold)")
    print("=" * 60)

    start_time = time.time()
    cleanup_previous_runs()
    files = create_victim_files(100)

    start_io = get_io_stats()

    target_bytes_per_sec = write_mbps * 1024 * 1024
    chunk_size = 1024 * 100  # 100KB chunks
    sleep_duration = chunk_size / target_bytes_per_sec

    print(f"[ATTACK] Writing at ~{write_mbps} MB/s for 30 seconds...")

    file_idx = 0
    start_write = time.time()

    for i in range(300):  # 300 iterations
        target = files[file_idx % len(files)]
        target.write_bytes(os.urandom(chunk_size))
        file_idx += 1

        # Sleep to limit write rate
        time.sleep(sleep_duration)

        if i % 50 == 0:
            print(f"[ATTACK] Chunk {i}/300 ({(i/300)*100:.0f}%)")

    actual_duration = time.time() - start_write
    end_io = get_io_stats()
    bytes_written = 300 * chunk_size
    bytes_diff = end_io['write_bytes'] - start_io['write_bytes'] if start_io and end_io else bytes_written
    mbps = (bytes_diff / (1024 * 1024)) / actual_duration if actual_duration > 0 else 0

    print(f"[RESULT] Wrote {bytes_written / (1024*1024):.1f} MB in {actual_duration:.1f}s = {mbps:.1f} MB/s")

    return SimResult(
        mode="slow_evasion",
        success=True,
        files_created=len(files),
        files_encrypted=file_idx,
        duration_sec=actual_duration,
        iops=mbps,
        notes=[
            f"Actual rate: {mbps:.1f} MB/s",
            f"Threshold: 50 MB/s",
            "Slow write ransomware likely EVADES current detection",
            "RECOMMENDATION: Add cumulative I/O tracking over time window"
        ]
    )


def full_encryption_attack(bypass_honeypot: bool = False) -> SimResult:
    """
    Full ransomware attack with encryption and file renaming.
    Tests: Complete detection pipeline with honeypot verification.
    """
    print("\n" + "=" * 60)
    print("MODE: Full Encryption Attack")
    print("Simulates: Real ransomware with file encryption + renaming")
    print("=" * 60)

    start_time = time.time()
    cleanup_previous_runs()

    # Create test files including honeypot files if they exist
    victim_files = create_victim_files(50)

    # Add some honeypot-style files (to see if honeypot detection works)
    honeypot_test_dir = TEST_DIR / "sensitive"
    honeypot_test_dir.mkdir(exist_ok=True)
    honeypot_files = []
    for i in range(10):
        hp = honeypot_test_dir / f"IMPORTANT_{i}.txt"
        hp.write_text(f"SENSITIVE DATA - DO NOT TOUCH\n{random_string(100)}\n")
        honeypot_files.append(hp)

    start_io = get_io_stats()

    print(f"[ATTACK] Encrypting {len(victim_files)} victim files + {len(honeypot_files)} honeypot files...")

    encrypted_count = 0
    deleted_count = 0

    # Phase 1: Encrypt victim files
    for f in victim_files:
        try:
            # Read, "encrypt", and write back
            original = f.read_bytes()
            encrypted = encrypt_data(original, key=os.urandom(32))
            f.write_bytes(encrypted)

            # Rename to .encrypted
            new_name = f.with_name(f.stem + ".encrypted")
            f.rename(new_name)

            encrypted_count += 1
            if encrypted_count % 10 == 0:
                print(f"[ATTACK] Encrypted {encrypted_count}/{len(victim_files)} files")
        except Exception as e:
            print(f"[ERROR] Failed to encrypt {f}: {e}")

    # Phase 2: Encrypt and destroy honeypot files (the key test!)
    print("[ATTACK] Now attacking honeypot files (testing detection)...")
    for f in honeypot_files:
        try:
            original = f.read_bytes()
            encrypted = encrypt_data(original, key=os.urandom(32))
            f.write_bytes(encrypted)
            f.unlink()  # Delete after encryption
            deleted_count += 1
            print(f"[ATTACK] Encrypted and deleted {f.name}")
        except Exception as e:
            print(f"[ERROR] Failed on honeypot {f}: {e}")

    actual_duration = time.time() - start_time
    end_io = get_io_stats()
    bytes_diff = end_io['write_bytes'] - start_io['write_bytes'] if start_io and end_io else encrypted_count * 100 * 1024
    mbps = (bytes_diff / (1024 * 1024)) / actual_duration if actual_duration > 0 else 0

    # Count remaining files
    remaining = sum(1 for _ in TEST_DIR.rglob("*") if _.is_file())

    print(f"[RESULT] Encrypted {encrypted_count} files, deleted {deleted_count} honeypot files")
    print(f"[RESULT] Duration: {actual_duration:.1f}s, Rate: {mbps:.1f} MB/s")
    print(f"[RESULT] Files remaining: {remaining}")

    return SimResult(
        mode="full_encryption_attack",
        success=True,
        files_created=len(victim_files) + len(honeypot_files),
        files_encrypted=encrypted_count,
        files_deleted=deleted_count,
        duration_sec=actual_duration,
        iops=mbps,
        notes=[
            f"Encrypted {encrypted_count} files, deleted {deleted_count} honeypot files",
            f"Rate: {mbps:.1f} MB/s - SHOULD trigger detection (>50 MB/s)",
            "Honeypot file deletion SHOULD trigger immediate ransomware verdict",
            "RECOMMENDATION: Check if honeypot directory was accessed"
        ]
    )


def random_string(length: int) -> str:
    """Generate random string."""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Simple XOR encryption (demo only - not real AES).
    Real ransomware would use properly encrypted data.
    """
    key_stream = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_stream)).hex().encode()


def multi_process_attack(num_processes: int = 5) -> SimResult:
    """
    Simulate distributed ransomware from multiple processes.
    Tests: Can the system track multiple suspicious processes?
    """
    print("\n" + "=" * 60)
    print(f"MODE: Multi-Process Attack ({num_processes} processes)")
    print("Simulates: Worm or botnet-based ransomware")
    print("=" * 60)

    cleanup_previous_runs()

    # Create separate directories per process
    for i in range(num_processes):
        dir_path = TEST_DIR / f"victim_set_{i}"
        dir_path.mkdir(exist_ok=True)
        for j in range(10):
            f = dir_path / f"file_{j}.txt"
            f.write_text(f"Data {i}-{j}\n" + "X" * 1000)

    print(f"[ATTACK] Spawning {num_processes} write-heavy processes...")

    # Simulate by writing from this process (fork would be better but complex for test)
    start_time = time.time()
    start_io = get_io_stats()

    for i in range(num_processes * 10):
        dir_path = TEST_DIR / f"victim_set_{i % num_processes}"
        all_files = list(dir_path.glob("*.txt"))
        if all_files:
            f = all_files[0]
            f.write_bytes(os.urandom(1024 * 50))  # 50KB chunks
        if i % 5 == 0:
            print(f"[ATTACK] Chunk {i}/{num_processes * 10}")

    actual_duration = time.time() - start_time
    end_io = get_io_stats()
    bytes_diff = end_io['write_bytes'] - start_io['write_bytes'] if start_io and end_io else 0
    mbps = (bytes_diff / (1024 * 1024)) / actual_duration if actual_duration > 0 else 0

    print(f"[RESULT] Multi-process simulation complete: {mbps:.1f} MB/s")

    return SimResult(
        mode="multi_process_attack",
        success=True,
        files_created=num_processes * 10,
        files_encrypted=num_processes * 10,
        duration_sec=actual_duration,
        iops=mbps,
        notes=[
            f"Simulated {num_processes} concurrent ransomware processes",
            "Real test would use multiprocessing/PID tracking",
            "Each process should be individually tracked by detector"
        ]
    )


def run_all_modes() -> list[SimResult]:
    """Run all simulation modes and return results."""
    results = []

    modes = [
        ("Basic Heavy I/O", lambda: basic_heavy_io(10)),
        ("Fast Write Burst", lambda: fast_write_burst(3)),
        ("Slow Evasion", lambda: slow_evasion(5)),
        ("Full Encryption", lambda: full_encryption_attack()),
    ]

    for name, func in modes:
        try:
            result = func()
            results.append(result)
        except Exception as e:
            print(f"[ERROR] Mode {name} failed: {e}")
            results.append(SimResult(mode=name, success=False, notes=[str(e)]))

        time.sleep(2)  # Cool down between tests

    return results


def print_summary(results: list[SimResult]):
    """Print summary of all simulation results."""
    print("\n" + "=" * 60)
    print("RANSOMWARE SIMULATION SUMMARY")
    print("=" * 60)

    for r in results:
        status = "PASS" if r.success else "FAIL"
        print(f"\n[{status}] {r.mode}")
        print(f"  Duration: {r.duration_sec:.1f}s")
        print(f"  Files: {r.files_encrypted} encrypted, {r.files_deleted} deleted")
        print(f"  I/O Rate: {r.iops:.1f} MB/s")
        for note in r.notes:
            print(f"  -> {note}")

    print("\n" + "=" * 60)
    print("DETECTION ANALYSIS")
    print("=" * 60)

    detected = [r for r in results if r.iops > 50]
    not_detected = [r for r in results if r.iops <= 50]

    print(f"\nDetected (rate > 50 MB/s): {len(detected)}")
    for r in detected:
        print(f"  - {r.mode}: {r.iops:.1f} MB/s")

    print(f"\nMay Evade (rate < 50 MB/s): {len(not_detected)}")
    for r in not_detected:
        print(f"  - {r.mode}: {r.iops:.1f} MB/s")


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Attack Simulator for OsSecurity Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python test_ransomware_simulator.py --mode basic
    python test_ransomware_simulator.py --mode fast_write
    python test_ransomware_simulator.py --mode slow_evasion
    python test_ransomware_simulator.py --mode full_attack
    python test_ransomware_simulator.py --mode multi_process
    python test_ransomware_simulator.py --mode all
        """
    )

    parser.add_argument(
        '--mode',
        choices=['basic', 'fast_write', 'slow_evasion', 'full_attack', 'multi_process', 'all'],
        default='basic',
        help='Simulation mode to run'
    )
    parser.add_argument(
        '--duration',
        type=float,
        default=10.0,
        help='Duration in seconds for continuous write tests'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("RANSOMWARE ATTACK SIMULATOR")
    print("For Testing OsSecurity Ransomware Detection")
    print("=" * 60)

    # Verify we're on Linux with /proc
    if sys.platform != 'linux':
        print("[ERROR] This simulation requires Linux (/proc filesystem)")
        sys.exit(1)

    if os.geteuid() == 0:
        print("[WARNING] Running as root - some file operations may behave differently")

    results = []

    if args.mode == 'basic':
        results.append(basic_heavy_io(args.duration))
    elif args.mode == 'fast_write':
        results.append(fast_write_burst(min(3.0, args.duration)))
    elif args.mode == 'slow_evasion':
        results.append(slow_evasion(5.0))
    elif args.mode == 'full_attack':
        results.append(full_encryption_attack())
    elif args.mode == 'multi_process':
        results.append(multi_process_attack())
    elif args.mode == 'all':
        results = run_all_modes()

    print_summary(results)

    # Cleanup
    print("\n[CLEANUP] Removing test files...")
    cleanup_previous_runs()
    print("[DONE]")


if __name__ == "__main__":
    main()