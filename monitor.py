import os
import time

# Threshold set to 50 MB/s as per instructions
THRESHOLD_MBPS = 50 

def get_all_pids():
    """List all numeric directories in /proc[cite: 22, 28]."""
    return [d for d in os.listdir('/proc') if d.isdigit()]

def get_process_name(pid):
    """Read the process name from /proc/<pid>/comm[cite: 26, 28]."""
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, ProcessLookupError):
        return "Unknown"

def read_proc_io(pid):
    """Parse /proc/<pid>/io into a dictionary of counters[cite: 23, 24, 28]."""
    io_data = {}
    try:
        with open(f'/proc/{pid}/io', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':')
                    io_data[key.strip()] = int(value.strip())
        return io_data
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        # Processes can disappear or be restricted; handle gracefully[cite: 29, 32].
        return None

def main():
    print("Starting I/O monitor... ")
    
    # Storage for the first set of readings: {pid: last_write_bytes}
    last_readings = {}

    try:
        while True:
            current_pids = get_all_pids()
            new_readings = {}

            for pid in current_pids:
                data = read_proc_io(pid)
                if data:
                    current_write = data.get('write_bytes', 0)
                    
                    # If we have a previous reading for this PID, calculate the rate [cite: 11]
                    if pid in last_readings:
                        bytes_diff = current_write - last_readings[pid]
                        
                        # Calculate rate (assuming ~1 second interval) [cite: 11]
                        # Convert bytes to Megabytes (MB = bytes / 1024 / 1024) [cite: 25]
                        mb_ps = bytes_diff / (1024 * 1024)
                        
                        if mb_ps > THRESHOLD_MBPS:
                            name = get_process_name(pid)
                            print(f"[Monitor] ALERT: PID {pid} ({name}) writing at {mb_ps:.2f} MB/s ")
                    
                    # Update our tracker with the current reading
                    new_readings[pid] = current_write
            
            # Carry current readings over to the next second
            last_readings = new_readings
            
            # Wait 1 second before the next check [cite: 11]
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping Monitor.")

if __name__ == "__main__":
    main()