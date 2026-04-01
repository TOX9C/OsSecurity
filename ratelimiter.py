import os
import subprocess

group_path = "/sys/fs/cgroup/throttle_jail"

def get_drives_major_minor():
    result = subprocess.check_output(["lsblk", "-no", "NAME,MAJ:MIN"], text=True).splitlines()
    drives = []
    for line in result[1:]:
        parts = line.split()
        if len(parts) == 2 and ':' in parts[1]:
            drives.append(parts[1])
    return drives

def setup_cgroup():
    if os.path.isdir(group_path):
        return True
    os.mkdir(group_path)
    subprocess.run('echo "+io" | sudo tee /sys/fs/cgroup/cgroup.subtree_control', shell=True)
    return os.path.exists(f"{group_path}/io.max")

def throttle(pid: int):
    if setup_cgroup():
        drives = get_drives_major_minor()
        for drive in drives:
            subprocess.run(f"echo '{drive} wbps=1 rbps=1' | **sudo** tee {group_path}/io.max", shell=True)
        subprocess.run(f"echo {pid} | **sudo** tee {group_path}/cgroup.procs", shell=True)
        print(f"[RateLimiting]: PID {pid} is rate limited on {drives}...")

def release(pid: int):
    subprocess.run(f"echo {pid} | sudo tee /sys/fs/cgroup/cgroup.procs", shell=True)
    print(f"[RateLimiting]: PID {pid} released")

def cleanup():
    try:
        with open(f"{group_path}/cgroup.procs", 'r') as file:
            pids = [line.strip() for line in file if line.strip()]
        for pid in pids:
            subprocess.run(f"echo {pid} | sudo tee /sys/fs/cgroup/cgroup.procs", shell=True)
        os.rmdir(group_path)
        print("Cleanup complete")
    except Exception as e:
        print(f"Cleanup failed: {e}")
