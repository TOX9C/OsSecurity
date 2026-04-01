# config.py — Detector configuration
# Tweak these values and discuss the reasoning in your report

# How fast is "suspiciously high" write speed (MB/s)
IO_THRESHOLD_MBPS = 50.0

# How many seconds of sustained high I/O before we escalate
SUSPICIOUS_DURATION_SEC = 5.0

# How long before we consider an alert "stale" and reset to NORMAL
# (i.e. the process stopped doing heavy I/O)
ALERT_EXPIRY_SEC = 3.0

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
