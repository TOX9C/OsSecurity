# config.py — Detector configuration
# Tweak these values and discuss the reasoning in your report

# How fast is "suspiciously high" write speed (MB/s)
IO_THRESHOLD_MBPS = 50.0

# How often the monitor polls /proc for I/O stats (seconds)
# Lower = faster detection, higher CPU usage
MONITOR_INTERVAL = 0.25

# How many seconds of sustained high I/O before we escalate
# (No longer used as a gate before throttling — throttle is immediate.
#  Kept for potential future use as a secondary confirmation window.)
SUSPICIOUS_DURATION_SEC = 3.0

# How long before we consider an alert "stale" and reset to NORMAL
# (i.e. the process stopped doing heavy I/O)
# Must be >= HONEYPOT_WATCH_SEC so throttled processes aren't cleared
# before the honeypot can verify them.
ALERT_EXPIRY_SEC = 10.0

# How long the honeypot watches decoy files before clearing a process
HONEYPOT_WATCH_SEC = 10.0

# Processes allowed to do heavy I/O without triggering investigation
WHITELISTED_PROCESSES = [
    # Package managers
    "apt", "apt-get", "dpkg", "yum", "dnf", "pacman", "pip", "pip3",

    # File operations
    "rsync", "cp", "mv", "tar", "zip", "unzip", "7z",

    # Disk operations
    "dd", "mkfs", "fsck",

    # Compilers / build tools
    "gcc", "g++", "make", "cmake", "cargo", "go",

    # Databases
    "mysqld", "postgres", "mongod", "redis-server",

    # Media
    "ffmpeg", "handbrake",

    # Containers / VMs
    "docker", "containerd", "virtualbox",

    # System
    "systemd", "journald", "svchost.exe", "msiexec.exe", "windows update",

    # Antivirus (ironic but necessary)
    "defender", "msmpeng.exe",
]
