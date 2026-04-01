import subprocess

def get_drives():
    result = subprocess.check_output(["lsblk","-o","MAJ:MIN"],text=True).splitlines()
    seen = set()
    driveList = []
    for i in result:
        if i[0] in seen:
            continue
        else:
            seen.add(i[0])
            driveList.append(i)
    print(driveList)
    return

