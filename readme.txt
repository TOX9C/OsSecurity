Our ransomware detector works like this:

YOU (Monitor) → feeds data to → Detector → tells → Rate Limiter + Honeypot → verdict

You are the EYES of the system. Without your component, nothing else works. The Detector can't flag anything suspicious if it doesn't have data. So your piece is the foundation.

━━━━━━━━━━━━━━━━━━━━━━━━━━
YOUR FINAL GOAL
━━━━━━━━━━━━━━━━━━━━━━━━━━

Build a Python module that runs in the background, checks every running process on the system once per second, calculates how fast each process is reading and writing to disk (in bytes per second), and if any process is writing faster than 50 MB/s, sends an alert to the Detector component.

Think of it like building a custom version of the "iotop" command that's already on Linux. Except instead of just displaying the info, you feed it into our detection pipeline.

By the end of this week, when you run your module standalone, it should print something like:
   [Monitor] ALERT: PID 4523 (dd) writing at 120.5 MB/s
   [Monitor] ALERT: PID 4523 (dd) writing at 118.2 MB/s
And those alerts should appear when you run a disk-heavy command like "dd" in another terminal.

━━━━━━━━━━━━━━━━━━━━━━━━━━
HOW IT WORKS — THE CORE CONCEPT
━━━━━━━━━━━━━━━━━━━━━━━━━━

Linux has a virtual filesystem called /proc. It's not a real folder with real files on disk — it's the kernel exposing information about running processes as if they were files. For every running process, there's a directory at /proc/<PID>/ with tons of info.

The file we care about is /proc/<PID>/io. Open a terminal on your VM and try this right now:

   cat /proc/self/io

You'll see something like:
   rchar: 4532
   wchar: 0
   syscr: 12
   syscw: 0
   read_bytes: 0
   write_bytes: 0
   cancelled_write_bytes: 0

The "read_bytes" and "write_bytes" lines are cumulative counters — total bytes ever read/written by this process since it started. They only go up, never down.

To get the RATE (bytes per second), you read these numbers, wait 1 second, read them again, and subtract:
   rate = (second_reading - first_reading) / time_elapsed

That's the entire core algorithm. Everything else is just plumbing around this idea.

━━━━━━━━━━━━━━━━━━━━━━━━━━
DAY 1 — RESEARCH (today)
━━━━━━━━━━━━━━━━━━━━━━━━━━

Goal: Understand the /proc filesystem and how to read process I/O stats.

1. PLAY WITH /proc ON YOUR VM
   Open a terminal and run these commands. Don't just read them — actually run them and look at the output:

   ls /proc/
   → You'll see numbered directories (those are PIDs) and other system files

   cat /proc/self/io
   → Shows I/O stats of the cat command itself

   cat /proc/1/comm
   → Shows the name of process 1 (should be "systemd")

   cat /proc/1/io
   → Might need sudo. Shows systemd's I/O stats

   sudo iotop -o
   → Shows real-time per-process I/O. THIS is what you're building. Play with it, open other terminals, copy files around, and watch the numbers change.

2. READ THE DOCUMENTATION
   The official docs for /proc. You don't need to read the whole thing — search for "proc/pid/io":
   https://www.kernel.org/doc/html/latest/filesystems/proc.html

   Or on your VM: man 5 proc (and search for /io)

3. OPTIONAL — LOOK AT PSUTIL
   psutil is a Python library that wraps all the /proc stuff in a clean API. You CAN use it, but I'd recommend going raw /proc first so you understand what's happening underneath. Then switch to psutil later if you want cleaner code.
   https://psutil.readthedocs.io/en/latest/

━━━━━━━━━━━━━━━━━━━━━━━━━━
DAY 2 — HANDS-ON EXPERIMENTS (tomorrow)
━━━━━━━━━━━━━━━━━━━━━━━━━━

Goal: Write tiny test scripts to prove you can do each piece.

EXPERIMENT 1: List all running PIDs
Open a Python shell (python3) on your VM and try:

   import os
   pids = [int(d) for d in os.listdir('/proc') if d.isdigit()]
   print(f"Found {len(pids)} running processes")
   print(pids[:10])

You should see a few hundred PIDs.

EXPERIMENT 2: Read I/O for one process
Pick a PID from the list above and try:

   pid = 1  # systemd, or use any PID
   with open(f'/proc/{pid}/io') as f:
       print(f.read())

If you get PermissionError, use sudo: sudo python3

EXPERIMENT 3: Parse the I/O file
Now parse it into numbers:

   def read_io(pid):
       with open(f'/proc/{pid}/io') as f:
           lines = f.readlines()
       data = {}
       for line in lines:
           key, value = line.strip().split(': ')
           data[key] = int(value)
       return data

   print(read_io(1))
   # Should print: {'rchar': ..., 'wchar': ..., 'read_bytes': ..., ...}

EXPERIMENT 4: Measure the rate
This is the key algorithm:

   import time
   pid = <pick_a_pid>
   reading1 = read_io(pid)
   time.sleep(2)
   reading2 = read_io(pid)
   write_rate = (reading2['write_bytes'] - reading1['write_bytes']) / 2
   print(f"Write rate: {write_rate / 1024 / 1024:.2f} MB/s")

TEST IT: while that's sleeping, run this in another terminal:
   dd if=/dev/zero of=/tmp/testfile bs=1M count=200
Then use dd's PID as <pick_a_pid> and you should see a high MB/s rate.

EXPERIMENT 5: Get a process name
   pid = 1
   with open(f'/proc/{pid}/comm') as f:
       name = f.read().strip()
   print(name)  # "systemd"

If ALL of these experiments work, you understand everything you need for your component.

━━━━━━━━━━━━━━━━━━━━━━━━━━
DAY 3-5 — CODING
━━━━━━━━━━━━━━━━━━━━━━━━━━

Open monitor.py from the repo. The skeleton is there with classes and function signatures.
Fill in the TODO functions in this order:

1. get_all_pids() → basically Experiment 1
2. get_process_name(pid) → basically Experiment 5
3. read_proc_io(pid) → basically Experiments 2+3, but return an IOReading object
4. IOMonitor.run() → the main loop, basically Experiment 4 but for ALL processes

IMPORTANT: Always wrap file reads in try/except FileNotFoundError — processes can die between when you list them and when you try to read their /proc files. This WILL happen and your code will crash if you don't handle it.

━━━━━━━━━━━━━━━━━━━━━━━━━━
HOW TO TEST
━━━━━━━━━━━━━━━━━━━━━━━━━━

Run: sudo python3 monitor.py

It should start printing "Starting I/O monitor..." and then sit there quietly.

Now open another terminal and run:
   dd if=/dev/zero of=/tmp/bigfile bs=1M count=1000

Your monitor should immediately print an ALERT showing dd's PID and its write rate.

If that works, your component is DONE for Week 1. 🎉

━━━━━━━━━━━━━━━━━━━━━━━━━━
PITFALLS TO WATCH OUT FOR
━━━━━━━━━━━━━━━━━━━━━━━━━━

• PermissionError: you need root (sudo) to read /proc/<pid>/io for all processes
• FileNotFoundError: processes die all the time, always use try/except
• PID reuse: a PID number can be reused for a new process after the old one dies. Compare process names between readings if you want to be safe.
• Division by zero: if time_delta is somehow 0, handle it
```
