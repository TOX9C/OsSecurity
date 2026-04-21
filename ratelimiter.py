"""
Rate Limiter — throttles process I/O via cgroups v2.

When a suspicious process is detected, we:
1. Create a cgroup: /sys/fs/cgroup/throttle_jail/
2. Set I/O limits: 1 MB/s read, 1 MB/s write
3. Move the process PID into that cgroup

When cleared:
1. Move PID back to root cgroup
2. Remove the throttle_jail cgroup

Requires: Linux + cgroups v2 + root/sudo
"""

import os
import subprocess
import logging

log = logging.getLogger("RateLimiter")

CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_JAIL = f"{CGROUP_ROOT}/throttle_jail"

# 1 MB/s = 1048576 bytes/s (cgroups uses bytes per second)
# "max" means no limit; we set rbps/wbps to 1048576
THROTTLE_READ_BPS = "1048576"    # 1 MB/s
THROTTLE_WRITE_BPS = "1048576"   # 1 MB/s


def get_drives_major_minor() -> list[str]:
    """Get major:minor pairs for whole disk devices only (not partitions).
    
    cgroups v2 io.max only accepts whole disk devices (e.g., 8:0 for sda),
    NOT partitions (e.g., 8:1 for sda1). Using partition major:minor numbers
    causes 'No such device' errors.
    """
    try:
        # -d = no partitions (whole disks only), -n = no header, -o = output columns
        result = subprocess.run(
            ["lsblk", "-dno", "MAJ:MIN"],
            capture_output=True, text=True, check=True
        )
        drives = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if ":" in line:
                drives.append(line)
        if drives:
            log.info(f"Found block devices: {drives}")
        return drives
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.warning(f"Could not list drives with lsblk: {e}")
        return []


def _write_cgroup_file(path: str, value: str) -> bool:
    """Write a value to a cgroup control file."""
    try:
        with open(path, 'w') as f:
            f.write(value)
        return True
    except (PermissionError, FileNotFoundError, OSError) as e:
        log.error(f"Failed to write '{value}' to {path}: {e}")
        return False


def _read_cgroup_file(path: str) -> str | None:
    """Read a value from a cgroup control file."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, OSError):
        return None


def setup_cgroup() -> bool:
    """Create the throttle_jail cgroup. Returns True if ready."""
    if os.path.isdir(CGROUP_JAIL) and os.path.isfile(f"{CGROUP_JAIL}/io.max"):
        # Clear any stale subtree_control from previous buggy runs
        # (subtree_control +io on the jail prevents adding processes)
        _write_cgroup_file(f"{CGROUP_JAIL}/cgroup.subtree_control", "-io")
        return True

    # Enable io controller in the root cgroup subtree
    _write_cgroup_file(f"{CGROUP_ROOT}/cgroup.subtree_control", "+io")

    # Create the child cgroup
    try:
        os.mkdir(CGROUP_JAIL)
    except FileExistsError:
        pass
    except PermissionError as e:
        log.error(f"Cannot create cgroup (need root): {e}")
        return False

    # Verify it exists
    if not os.path.isfile(f"{CGROUP_JAIL}/io.max"):
        log.error("cgroup io.max not found after creation — cgroups v2 may not be available")
        return False

    # NOTE: Do NOT enable subtree_control +io on the jail cgroup itself.
    # In cgroups v2, a cgroup with controllers in subtree_control becomes
    # an "internal" node and CANNOT have processes in it directly.
    # The jail is a leaf cgroup — processes go here, not in children.

    log.info(f"cgroup jail created: {CGROUP_JAIL}")
    return True


def throttle(pid: int) -> bool:
    """
    Throttle a process to 1 MB/s read/write by moving it into
    the throttle_jail cgroup with I/O limits.
    """
    if not setup_cgroup():
        log.error("Cannot throttle — cgroup setup failed")
        return False

    drives = get_drives_major_minor()
    if not drives:
        # Fallback: use "default" which applies to all devices
        drives = ["*"]

    # Set I/O limits on all drives
    for drive in drives:
        # Format: "MAJ:MIN rbps=VALUE wbps=VALUE"
        limit_str = f"{drive} rbps={THROTTLE_READ_BPS} wbps={THROTTLE_WRITE_BPS}"
        if not _write_cgroup_file(f"{CGROUP_JAIL}/io.max", limit_str):
            log.warning(f"Failed to set I/O limit for drive {drive}")

    # Move the process into the jail cgroup
    pid_str = str(pid)
    if _write_cgroup_file(f"{CGROUP_JAIL}/cgroup.procs", pid_str):
        log.info(f"PID {pid} throttled to 1 MB/s in cgroup jail")
        return True
    else:
        log.error(f"Failed to move PID {pid} into cgroup jail")
        return False


def release(pid: int) -> bool:
    """Move a process back to the root cgroup (remove throttle)."""
    pid_str = str(pid)
    if _write_cgroup_file(f"{CGROUP_ROOT}/cgroup.procs", pid_str):
        log.info(f"PID {pid} released from cgroup jail")
        return True
    else:
        log.error(f"Failed to release PID {pid} from cgroup jail")
        return False


def cleanup() -> None:
    """Move all jailed processes back to root and remove the jail cgroup."""
    procs_content = _read_cgroup_file(f"{CGROUP_JAIL}/cgroup.procs")
    if procs_content:
        for pid_str in procs_content.splitlines():
            pid_str = pid_str.strip()
            if pid_str:
                _write_cgroup_file(f"{CGROUP_ROOT}/cgroup.procs", pid_str)
                log.info(f"Released PID {pid_str} during cleanup")

    # Remove I/O limits
    drives = get_drives_major_minor()
    for drive in drives or ["*"]:
        _write_cgroup_file(f"{CGROUP_JAIL}/io.max", f"{drive} rbps=max wbps=max")

    # Remove the cgroup directory
    try:
        os.rmdir(CGROUP_JAIL)
        log.info("cgroup jail removed")
    except OSError as e:
        log.warning(f"Could not remove cgroup jail: {e}")
