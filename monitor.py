import os
import time

# Threshold set to 50 MB/s as per project requirements [cite: 37]
THRESHOLD_MBPS = 50 

def get_all_pids():
    """List all numeric directories in /proc[cite: 56]."""
    return [d for d in os.listdir('/proc') if d.isdigit()]

def get_process_name(pid):
    """Read the process name from /proc/<pid>/comm[cite: 60]."""
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, ProcessLookupError):
        return "Unknown"

def read_proc_io(pid):
    """Parse /proc/<pid>/io into a dictionary of counters[cite: 57, 58]."""
    io_data = {}
    try:
        with open(f'/proc/{pid}/io', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':')
                    io_data[key.strip()] = int(value.strip())
        return io_data
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        # Handle processes that vanish between snapshots [cite: 62, 63, 66]
        return None

def main():
    print("Starting I/O monitor...")
    
    # Storage for previous readings: {pid: last_write_bytes}
    last_readings = {}

    try:
        while True:
            current_pids = get_all_pids()
            new_readings = {}

            for pid in current_pids:
                data = read_proc_io(pid)
                if data:
                    # Target 'write_bytes' for ransomware detection [cite: 44, 45]
                    current_write = data.get('write_bytes', 0)
                    
                    if pid in last_readings:
                        # Calculate difference between snapshots [cite: 45, 59]
                        bytes_diff = current_write - last_readings[pid]
                        
                        # Convert bytes to Megabytes (MB = bytes / 1024 / 1024) [cite: 59]
                        mb_ps = bytes_diff / (1024 * 1024)
                        
                        name = get_process_name(pid)
                        
                        # DEBUG: Ensure script is seeing the 'dd' command
                        if name == "dd" and mb_ps > 0:
                            print(f"[Debug] Caught dd (PID {pid}) writing at {mb_ps:.2f} MB/s")

                        # Alert logic for threshold [cite: 37, 40]
                        if mb_ps > THRESHOLD_MBPS:
                            print(f"[Monitor] ALERT: PID {pid} ({name}) writing at {mb_ps:.2f} MB/s")
                    
                    new_readings[pid] = current_write
            
            last_readings = new_readings
            
            # 1 second interval for rate calculation [cite: 45, 64]
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping Monitor.")

if __name__ == "__main__":
    main()