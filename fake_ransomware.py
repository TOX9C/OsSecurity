#!/usr/bin/env python3
"""
Fake Ransomware — Safe test script for OsSecurity detection system.

Creates realistic files in user directories, then encrypts them
with high I/O to trigger the ransomware detection pipeline.

Usage:
  Terminal 1: sudo python3 main.py          # Detection system
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

# Directories ransomware typically targets
TARGET_DIRS = [
    Path.home() / "Documents" / "test_victims",
    Path.home() / "Desktop" / "test_victims",
    Path.home() / "Pictures" / "test_victims",
]

# File types ransomware cares about
FILE_EXTENSIONS = [
    ".txt", ".doc", ".docx", ".xls", ".xlsx",
    ".pdf", ".jpg", ".png", ".csv", ".json",
]


def create_victim_files() -> list[Path]:
    """Create realistic file structures in user directories."""
    all_files = []

    for target_dir in TARGET_DIRS:
        target_dir.mkdir(parents=True, exist_ok=True)

        # Create sub-directories like a real user would have
        subdirs = ["work", "personal", "projects", "finances"]
        for subdir_name in subdirs:
            subdir = target_dir / subdir_name
            subdir.mkdir(exist_ok=True)

            # Create files in each subdirectory
            for i in range(8):
                ext = FILE_EXTENSIONS[(i + hash(subdir_name)) % len(FILE_EXTENSIONS)]
                file_path = subdir / f"document_{i:03d}{ext}"
                if ext == ".jpg":
                    # Fake image — random bytes that look like binary
                    file_path.write_bytes(os.urandom(50 * 1024))  # 50KB
                elif ext == ".pdf":
                    # Fake PDF header + random content
                    content = b"%PDF-1.4\n" + os.urandom(100 * 1024)  # 100KB
                    file_path.write_bytes(content)
                elif ext in (".xlsx", ".docx"):
                    # Fake office document — larger to look real
                    file_path.write_bytes(os.urandom(80 * 1024))  # 80KB
                else:
                    # Text-based files
                    content = f"Important Document #{i}\n"
                    content += "=" * 50 + "\n"
                    content += f"Category: {subdir_name}\n"
                    content += f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    content += "=" * 50 + "\n"
                    content += "Confidential data: " + "X" * 200 + "\n"
                    file_path.write_text(content)

                all_files.append(file_path)

        # Also put some files directly in the target dir
        for i in range(5):
            ext = FILE_EXTENSIONS[i % len(FILE_EXTENSIONS)]
            file_path = target_dir / f"important_{i:03d}{ext}"
            file_path.write_text(f"Top-level document {i}\n" + "A" * 500 + "\n")
            all_files.append(file_path)

    # Also create files in the shared victim root for good measure
    VICTIM_ROOT.mkdir(parents=True, exist_ok=True)
    for i in range(20):
        ext = FILE_EXTENSIONS[i % len(FILE_EXTENSIONS)]
        file_path = VICTIM_ROOT / f"file_{i:03d}{ext}"
        file_path.write_bytes(os.urandom(100 * 1024))  # 100KB each
        all_files.append(file_path)

    print(f"[CREATE] Created {len(all_files)} files across {len(TARGET_DIRS)} directories + {VICTIM_ROOT}")
    for d in TARGET_DIRS:
        count = sum(1 for _ in d.rglob("*") if _.is_file())
        print(f"  {d}: {count} files")
    return all_files


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR encryption (safe demo — not real crypto)."""
    key_stream = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_stream))


def encrypt_files(duration_sec: float = 30.0) -> None:
    """
    Walk user directories and encrypt files — mimics real ransomware.

    This should trigger:
    1. Monitor: high write_bytes above 50 MB/s
    2. Detector: SUSPICIOUS after 5s sustained
    3. Honeypot: decoy files get encrypted → RANSOMWARE CONFIRMED
    4. Detector: process killed
    """
    print(f"\n[ATTACK] Starting encryption attack for up to {duration_sec}s...")
    print(f"[ATTACK] PID: {os.getpid()} (watch for this in the detector logs)")
    print()

    # Collect all target files
    all_files: list[Path] = []
    for target_dir in TARGET_DIRS:
        if target_dir.exists():
            all_files.extend(f for f in target_dir.rglob("*") if f.is_file() and not f.name.endswith(".encrypted"))
    if VICTIM_ROOT.exists():
        all_files.extend(f for f in VICTIM_ROOT.rglob("*") if f.is_file() and not f.name.endswith(".encrypted"))

    if not all_files:
        print("[ERROR] No files found. Run 'create' first.")
        return

    print(f"[ATTACK] Found {len(all_files)} files to encrypt")

    start_time = time.time()
    bytes_written = 0
    encrypted_count = 0
    key = os.urandom(32)

    # Write a ransom note (classic ransomware behavior)
    for target_dir in TARGET_DIRS:
        if target_dir.exists():
            note = target_dir / "README_DECRYPT_YOUR_FILES.txt"
            note.write_text(
                "ATTENTION: Your files have been encrypted!\n"
                "Send 1 BTC to recover your data.\n"
                "[This is a SAFE TEST — OsSecurity detection test]\n"
            )

    # Encrypt files in a loop — keep writing to maintain high I/O
    end_time = start_time + duration_sec
    file_idx = 0

    while time.time() < end_time:
        if not all_files:
            # Re-scan for any unencrypted files
            all_files = []
            for target_dir in TARGET_DIRS:
                if target_dir.exists():
                    all_files.extend(f for f in target_dir.rglob("*") if f.is_file() and not f.name.endswith(".encrypted"))

        if not all_files:
            print("[ATTACK] All files encrypted — rewriting to maintain I/O")
            # Re-encrypt already-encrypted files to keep I/O high
            all_files = []
            for target_dir in TARGET_DIRS:
                if target_dir.exists():
                    all_files.extend(f for f in target_dir.rglob("*.encrypted") if f.is_file())

            if not all_files:
                print("[ATTACK] No files to work with. Stopping.")
                break

            # Overwrite encrypted files with new random data (sustained I/O)
            target = all_files[file_idx % len(all_files)]
            try:
                target.write_bytes(os.urandom(200 * 1024))  # 200KB per write
                bytes_written += 200 * 1024
            except (PermissionError, OSError):
                pass
            file_idx += 1
        else:
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

            except (PermissionError, OSError) as e:
                # Can't access this file — skip (dotfiles, system files etc.)
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

        # Small batch write to spike I/O — write extra random data
        if file_idx % 5 == 0:
            burst_file = VICTIM_ROOT / f"burst_{file_idx}.tmp"
            try:
                burst_file.write_bytes(os.urandom(1024 * 1024))  # 1MB burst
                bytes_written += 1024 * 1024
                burst_file.unlink(missing_ok=True)
            except OSError:
                pass

    actual_duration = time.time() - start_time
    mbps = (bytes_written / (1024 * 1024)) / actual_duration if actual_duration > 0 else 0

    print(f"\n[DONE] Encryption stopped after {actual_duration:.1f}s")
    print(f"[DONE] {encrypted_count} files encrypted, {bytes_written / (1024*1024):.1f} MB written")
    print(f"[DONE] Average rate: {mbps:.1f} MB/s")
    if mbps > 50:
        print("[DONE] Rate EXCEEDS 50 MB/s threshold — SHOULD be detected")
    else:
        print(f"[DONE] Rate below 50 MB/s threshold — may evade detection")


def cleanup_files() -> None:
    """Remove all test files and encrypted artifacts."""
    print("[CLEANUP] Removing test files...")

    for target_dir in TARGET_DIRS:
        if target_dir.exists():
            # Remove files (including .encrypted variants)
            for f in target_dir.rglob("*"):
                if f.is_file():
                    try:
                        f.unlink()
                    except OSError:
                        pass
            # Remove subdirectories
            for d in sorted(target_dir.rglob("*"), reverse=True):
                if d.is_dir():
                    try:
                        d.rmdir()
                    except OSError:
                        pass
            # Remove the target_dir itself
            try:
                target_dir.rmdir()
            except OSError:
                pass
            print(f"  Cleaned: {target_dir}")

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
