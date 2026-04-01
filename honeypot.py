import subprocess
import inotify.adapters
import os

HONEYPOT_DIR = "/opt/honeypot"
BAIT_FILES = [""]

def create_honeypot():
    """
    Creates the honeypot directory and populates it with realistic bait files.
    This is idempotent: it resets the honeypot if files already exist.
    """
    print(f"[Honeypot] Creating honeypot at {HONEYPOT_DIR}...")

    # 1. Create the directory if it doesn't exist
    try:
        os.makedirs(HONEYPOT_DIR, exist_ok=True)
    except OSError as e:
        print(f"[Error] Could not create directory {HONEYPOT_DIR}: {e}")
        return

    # 2. Populate the directory with bait files
    for filename, content in BAIT_FILES.items():
        filepath = os.path.join(HONEYPOT_DIR, filename)
        
        try:
            with open(filepath, "w") as f:
                f.write(content)
            print(f"  - Created: {filename}")
        except Exception as e:
            print(f"  - Failed to create {filename}: {e}")

    print("[Honeypot] Setup complete. Bait is in place.\n")



def run(self):
    print(f"[Honeypot] Monitoring {HONEYPOT_DIR}...")
    
    # Initialize the watcher on the honeypot directory
    i = inotify.adapters.InotifyTree(HONEYPOT_DIR)

    for event in i.event_gen(yield_nops=False):
        if not self.running:
            break

        (_, type_names, path, filename) = event
        
        # We care about: Modify, Delete, or Rename
        triggers = {'IN_MODIFY', 'IN_DELETE', 'IN_MOVED_FROM'}
        if any(t in type_names for t in triggers):
            full_path = os.path.join(path, filename)
            print(f"[!] Honeypot trigger: {filename} was accessed!")

            # Detective work: Who did it?
            pid = check_who_modified(full_path)

            # If the PID is one we were already watching, it's definitely Ransomware
            if pid in self.watching_pids:
                print(f"  --> VERDICT: PID {pid} is Ransomware!")
                self.verdict_queue.put((pid, True))
            
            # If we missed the PID but we have processes under investigation, 
            # we assume the worst for safety.


def check_who_modified(filepath: str) -> int | None:
    """
    Finds which PID has a specific file open using the 'lsof' command.
    """
    try:
        # Run 'lsof -t' (terse mode) which returns only the PID
        result = subprocess.run(
            ['lsof', '-t', filepath], 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        # Get the output and strip whitespace
        output = result.stdout.strip()
        
        if output:
            # If multiple PIDs are returned, we'll take the first one
            pid = int(output.split('\n')[0])
            return pid
            
    except Exception as e:
        print(f"[Honeypot] Error running lsof: {e}")
        
    return None
