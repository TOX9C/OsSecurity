import time
import queue
import random
import logging
import threading
from pathlib import Path
from dataclasses import dataclass

log = logging.getLogger("Honeypot")

HONEYPOT_META_DIR = Path("/tmp/honeypot_meta")


@dataclass
class HoneypotFile:
    """Decoy file created to detect ransomware behavior."""
    path: Path
    content_hash: str


@dataclass
class Verdict:
    """Message format from Honeypot → Detector."""
    pid: int
    is_ransomware: bool


class Honeypot:
    """
    Creates and monitors decoy files in user directories to detect ransomware.

    When deployed for a suspicious process, it:
    1. Plants decoy files in directories ransomware targets (Desktop, Documents, etc.)
    2. Hides them with a dot-prefix so the user doesn't accidentally modify them
    3. Watches for modifications — if files are encrypted/modified/deleted,
       the process is confirmed as ransomware
    """

    def __init__(self, verdict_queue: queue.Queue, watch_duration: float = 5.0,
                 target_dirs: list[Path] | None = None):
        self.verdict_queue = verdict_queue
        self.watch_duration = watch_duration
        self._active_watches: dict[int, threading.Thread] = {}
        self._files: dict[int, list[HoneypotFile]] = {}

        if target_dirs:
            self._target_dirs = target_dirs
        else:
            self._target_dirs = self._get_default_target_dirs()

    @staticmethod
    def _get_default_target_dirs() -> list[Path]:
        """Find user directories that ransomware typically targets."""
        home = Path.home()
        candidates = [
            home / "Desktop",
            home / "Documents",
            home / "Pictures",
            home / "Downloads",
            home / "Music",
            home / "Videos",
        ]
        return [d for d in candidates if d.is_dir()]

    def deploy_for_process(self, pid: int):
        """
        Deploy honeypot files and start monitoring for the given process.
        """
        if pid in self._active_watches:
            log.info(f"Already watching PID {pid}")
            return

        honeypot_files = self._create_decoy_files(pid)
        self._files[pid] = honeypot_files

        if not honeypot_files:
            log.warning(f"No directories available to plant honeypot for PID {pid}")
            self._report_verdict(pid, is_ransomware=False, reason="no target directories")
            return

        thread = threading.Thread(
            target=self._watch_files,
            args=(pid, honeypot_files),
            daemon=True,
            name=f"Honeypot-{pid}"
        )
        thread.start()
        self._active_watches[pid] = thread
        log.info(f"Deployed honeypot for PID {pid} with {len(honeypot_files)} decoy files "
                 f"across {len(self._target_dirs)} directories")

    def _create_decoy_files(self, pid: int) -> list[HoneypotFile]:
        """Create decoy files in user directories where ransomware will find them."""
        decoy_files = []

        # File types that ransomware specifically targets
        extensions = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.txt']

        for target_dir in self._target_dirs:
            # Use dot-prefix so user doesn't accidentally touch them
            # but ransomware's recursive walk will still find them
            for i, ext in enumerate(extensions):
                file_name = f".HONEYPOT_{pid}_{i}{ext}"
                file_path = target_dir / file_name

                # Generate identifiable content
                content = f"HONEYPOT_FILE_{pid}_{i}_{random.randint(100000, 999999)}\n"
                content += "SECURITY_MONITORING_FILE - DO NOT MODIFY\n"
                content += "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=1000))

                try:
                    file_path.write_text(content)
                    content_hash = str(hash(content))
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
        """Monitor honeypot files for modifications."""
        start_time = time.time()
        check_interval = 0.5

        while time.time() - start_time < self.watch_duration:
            for hf in honeypot_files:
                if not hf.path.exists():
                    # File was deleted — strong ransomware signal
                    self._report_verdict(pid, is_ransomware=True, reason="decoy file deleted")
                    return

                try:
                    current_hash = str(hash(hf.path.read_text()))
                    if current_hash != hf.content_hash:
                        # File was modified — encryption detected
                        self._report_verdict(pid, is_ransomware=True, reason="decoy file modified (encrypted)")
                        return
                except (PermissionError, OSError):
                    # If we can't read it anymore, it may have been locked by encryption
                    self._report_verdict(pid, is_ransomware=True, reason="decoy file became unreadable")
                    return

            time.sleep(check_interval)

        # Watch duration elapsed without detecting ransomware activity
        self._report_verdict(pid, is_ransomware=False, reason="no malicious activity detected")
        self._cleanup(pid)

    def _report_verdict(self, pid: int, is_ransomware: bool, reason: str):
        """Send verdict back to the detector."""
        verdict = Verdict(pid=pid, is_ransomware=is_ransomware)
        self.verdict_queue.put(verdict)

        if is_ransomware:
            log.critical(f"RANSOMWARE CONFIRMED for PID {pid}: {reason}")
        else:
            log.info(f"PID {pid} cleared: {reason}")

    def _cleanup(self, pid: int):
        """Remove honeypot decoy files and metadata."""
        # Remove decoy files from user directories
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
