import os
import time
import queue
import random
import logging
import threading
from pathlib import Path
from dataclasses import dataclass

from detector import Verdict

log = logging.getLogger("Honeypot")

HONEYPOT_META_DIR = Path("/tmp/honeypot_meta")

# Sentinel file prefix — pre-deployed at startup, always present
SENTINEL_PREFIX = ".SECURITY_SENTINEL_"
# Process-specific honeypot prefix — deployed when a suspicious process is detected
PROCESS_PREFIX = ".HONEYPOT_"


@dataclass
class HoneypotFile:
    """Decoy file created to detect ransomware behavior."""
    path: Path
    content_hash: str


class Honeypot:
    """
    Creates and monitors decoy files in user directories to detect ransomware.

    Two layers of protection:
    1. SENTINEL FILES — pre-deployed at startup in all user directories.
       These are already in place when ransomware starts, so they get
       encrypted during the ransomware's initial file walk.
    2. PROCESS-SPECIFIC FILES — deployed when a suspicious process is detected.
       Additional decoys as a backup layer.

    When any decoy file is modified/deleted/encrypted, the process is
    confirmed as ransomware and killed.
    """

    def __init__(self, verdict_queue: queue.Queue, watch_duration: float = 5.0,
                 target_dirs: list[Path] | None = None):
        self.verdict_queue = verdict_queue
        self.watch_duration = watch_duration
        self._active_watches: dict[int, threading.Thread] = {}
        self._files: dict[int, list[HoneypotFile]] = {}
        self._sentinel_files: list[HoneypotFile] = []

        if target_dirs:
            self._target_dirs = target_dirs
        else:
            self._target_dirs = self._get_default_target_dirs()

        # Pre-deploy sentinel files at initialization
        self._deploy_sentinels()

    @staticmethod
    def _get_default_target_dirs() -> list[Path]:
        """Find user directories that ransomware typically targets.
        
        When running as root (sudo), Path.home() returns /root which
        typically has no Desktop/Documents/etc. We also scan /home/*
        to find real user directories where files actually live.
        """
        subdirs = ["Desktop", "Documents", "Pictures", "Downloads", "Music", "Videos"]
        homes_to_check = [Path.home()]

        # When running as root, also scan all real user home directories
        home_base = Path("/home")
        if home_base.is_dir():
            try:
                for user_dir in home_base.iterdir():
                    if user_dir.is_dir() and user_dir not in homes_to_check:
                        homes_to_check.append(user_dir)
            except PermissionError:
                pass

        candidates = []
        for home in homes_to_check:
            for sub in subdirs:
                candidates.append(home / sub)

        found = [d for d in candidates if d.is_dir()]
        if found:
            log.info(f"Found {len(found)} target directories for honeypot")
        else:
            log.warning("No target directories found for honeypot deployment")
        return found

    def _deploy_sentinels(self):
        """Pre-deploy sentinel honeypot files in all target directories.
        
        These files are created at system startup BEFORE any ransomware
        runs. This ensures they are included in the ransomware's initial
        file walk and will be encrypted during the first pass.
        
        This solves the timing problem where process-specific honeypot
        files are deployed too late (after ransomware already collected
        its file list).
        """
        if not self._target_dirs:
            log.warning("No target directories — cannot deploy sentinel files")
            return

        # File types that ransomware specifically targets
        extensions = ['.doc', '.docx', '.xls', '.pdf', '.jpg', '.png', '.txt']

        for target_dir in self._target_dirs:
            for i, ext in enumerate(extensions):
                file_name = f"{SENTINEL_PREFIX}{i}{ext}"
                file_path = target_dir / file_name

                # Generate identifiable content
                content = f"SENTINEL_FILE_{i}_{random.randint(100000, 999999)}\n"
                content += "SECURITY_MONITORING_FILE - DO NOT MODIFY\n"
                content += "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=1000))

                try:
                    file_path.write_text(content)
                    content_hash = str(hash(content.encode('utf-8')))
                    self._sentinel_files.append(HoneypotFile(path=file_path, content_hash=content_hash))
                except (PermissionError, OSError) as e:
                    log.debug(f"Cannot create sentinel at {file_path}: {e}")

        if self._sentinel_files:
            log.info(f"Pre-deployed {len(self._sentinel_files)} sentinel files "
                     f"across {len(self._target_dirs)} directories")
        else:
            log.warning("Failed to deploy any sentinel files")

    def deploy_for_process(self, pid: int):
        """
        Deploy honeypot files and start monitoring for the given process.
        
        Monitors BOTH:
        - Pre-deployed sentinel files (already in directories)
        - Newly created process-specific decoy files
        """
        if pid in self._active_watches:
            log.info(f"Already watching PID {pid}")
            return

        # Create process-specific decoy files as additional layer
        process_files = self._create_decoy_files(pid)
        self._files[pid] = process_files

        # Combine sentinel files + process-specific files for monitoring
        all_watch_files = list(self._sentinel_files) + process_files

        if not all_watch_files:
            log.warning(f"No honeypot files available to watch for PID {pid}")
            self._report_verdict(pid, is_ransomware=False, reason="no honeypot files")
            return

        thread = threading.Thread(
            target=self._watch_files,
            args=(pid, all_watch_files),
            daemon=True,
            name=f"Honeypot-{pid}"
        )
        thread.start()
        self._active_watches[pid] = thread

        sentinel_count = len(self._sentinel_files)
        process_count = len(process_files)
        log.info(f"Watching {sentinel_count} sentinel + {process_count} new decoys "
                 f"for PID {pid}")

    def _create_decoy_files(self, pid: int) -> list[HoneypotFile]:
        """Create process-specific decoy files in user directories."""
        decoy_files = []

        # File types that ransomware specifically targets
        extensions = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.txt']

        for target_dir in self._target_dirs:
            # Use dot-prefix so user doesn't accidentally touch them
            # but ransomware's recursive walk will still find them
            for i, ext in enumerate(extensions):
                file_name = f"{PROCESS_PREFIX}{pid}_{i}{ext}"
                file_path = target_dir / file_name

                # Generate identifiable content
                content = f"HONEYPOT_FILE_{pid}_{i}_{random.randint(100000, 999999)}\n"
                content += "SECURITY_MONITORING_FILE - DO NOT MODIFY\n"
                content += "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=1000))

                try:
                    file_path.write_text(content)
                    content_hash = str(hash(content.encode('utf-8')))
                    decoy_files.append(HoneypotFile(path=file_path, content_hash=content_hash))
                    log.debug(f"Created decoy: {file_path}")
                except (PermissionError, OSError) as e:
                    log.warning(f"Cannot create decoy at {file_path}: {e}")

        # Also store metadata so we can clean up reliably
        meta_dir = HONEYPOT_META_DIR / str(pid)
        meta_dir.mkdir(parents=True, exist_ok=True)
        meta_file = meta_dir / "files.list"
        meta_file.write_text("\n".join(str(hf.path) for hf in decoy_files))

        return decoy_files

    def _watch_files(self, pid: int, honeypot_files: list[HoneypotFile]):
        """Monitor honeypot files for modifications.
        
        Checks for three signals:
        1. File deleted (path no longer exists)
        2. File renamed to .encrypted (common ransomware behavior)
        3. File content modified (hash changed)
        4. File became unreadable (locked/corrupted by encryption)
        """
        start_time = time.time()
        check_interval = 0.5

        while time.time() - start_time < self.watch_duration:
            for hf in honeypot_files:
                # Check 1: File deleted
                if not hf.path.exists():
                    # Check 1b: File renamed to .encrypted (ransomware signature)
                    encrypted_path = hf.path.with_suffix(hf.path.suffix + ".encrypted")
                    if encrypted_path.exists():
                        self._report_verdict(pid, is_ransomware=True,
                                             reason=f"decoy file renamed to .encrypted: {hf.path.name}")
                    else:
                        self._report_verdict(pid, is_ransomware=True,
                                             reason=f"decoy file deleted: {hf.path.name}")
                    return

                try:
                    # Use read_bytes to handle both text and binary content
                    # (XOR-encrypted files produce binary data that read_text() can't decode)
                    current_bytes = hf.path.read_bytes()
                    current_hash = str(hash(current_bytes))
                    if current_hash != hf.content_hash:
                        # File was modified — encryption detected
                        self._report_verdict(pid, is_ransomware=True,
                                             reason=f"decoy file modified (encrypted): {hf.path.name}")
                        return
                except (PermissionError, OSError, ValueError):
                    # If we can't read it anymore, it may have been locked by encryption
                    self._report_verdict(pid, is_ransomware=True,
                                         reason=f"decoy file became unreadable: {hf.path.name}")
                    return

            time.sleep(check_interval)

        # Watch duration elapsed without detecting ransomware activity
        self._report_verdict(pid, is_ransomware=False, reason="no malicious activity detected")
        self._cleanup_process_files(pid)

    def _report_verdict(self, pid: int, is_ransomware: bool, reason: str):
        """Send verdict back to the detector."""
        verdict = Verdict(pid=pid, is_ransomware=is_ransomware)
        self.verdict_queue.put(verdict)

        if is_ransomware:
            log.critical(f"RANSOMWARE CONFIRMED for PID {pid}: {reason}")
        else:
            log.info(f"PID {pid} cleared: {reason}")

    def _cleanup_process_files(self, pid: int):
        """Remove process-specific honeypot files and metadata.
        
        NOTE: Sentinel files are NOT removed — they persist for future detections.
        """
        # Remove process-specific decoy files
        if pid in self._files:
            for hf in self._files[pid]:
                try:
                    hf.path.unlink(missing_ok=True)
                except OSError:
                    pass
            del self._files[pid]

        # Remove metadata directory
        meta_dir = HONEYPOT_META_DIR / str(pid)
        if meta_dir.exists():
            for f in meta_dir.iterdir():
                f.unlink(missing_ok=True)
            try:
                meta_dir.rmdir()
            except OSError:
                pass

        if pid in self._active_watches:
            del self._active_watches[pid]

    def cleanup_all(self):
        """Remove ALL honeypot files (sentinels + process-specific). Called at shutdown."""
        # Remove sentinel files
        for hf in self._sentinel_files:
            try:
                hf.path.unlink(missing_ok=True)
            except OSError:
                pass
        self._sentinel_files.clear()
        log.info("Sentinel files cleaned up")

        # Remove any remaining process-specific files
        for pid in list(self._files.keys()):
            self._cleanup_process_files(pid)
