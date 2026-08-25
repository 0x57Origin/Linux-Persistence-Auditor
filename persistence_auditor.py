"""
Linux Persistence Auditor

A read-only defensive tool that inventories the locations attackers most
commonly use to gain persistence on a Linux host. It does not modify
anything. It reports what is present so a defender can review for
anything unexpected.

Usage:
    python3 persistence_auditor.py
"""

import os
import glob
from pathlib import Path

HOME = str(Path.home())

# Common persistence locations, grouped by category. These are the places
# a defender should routinely review during a host audit.
LOCATIONS = {
    "Cron jobs (system)": ["/etc/crontab", "/etc/cron.d/*", "/etc/cron.daily/*",
                            "/etc/cron.hourly/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*"],
    "Cron jobs (user)": [f"{HOME}/.crontab", "/var/spool/cron/crontabs/*"],
    "Systemd units (system)": ["/etc/systemd/system/*.service"],
    "Systemd units (user)": [f"{HOME}/.config/systemd/user/*.service"],
    "Shell startup files": [f"{HOME}/.bashrc", f"{HOME}/.bash_profile",
                            f"{HOME}/.profile", f"{HOME}/.zshrc", "/etc/profile",
                            "/etc/bash.bashrc"],
    "Autostart entries": [f"{HOME}/.config/autostart/*.desktop",
                          "/etc/xdg/autostart/*.desktop"],
    "Boot scripts": ["/etc/rc.local", "/etc/init.d/*"],
    "SSH authorized keys": [f"{HOME}/.ssh/authorized_keys"],
}


def resolve(patterns):
    """Expand glob patterns into a sorted list of existing paths."""
    found = []
    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.exists(path):
                found.append(path)
    return sorted(set(found))


def describe(path):
    """Return a short one-line note about a path for the report."""
    try:
        stat = os.stat(path)
        size = stat.st_size
        owner = stat.st_uid
        world_writable = bool(stat.st_mode & 0o002)
        flag = "  [!] WORLD-WRITABLE" if world_writable else ""
        return f"    {path}  (uid={owner}, {size} bytes){flag}"
    except OSError as e:
        return f"    {path}  (could not stat: {e})"


def main():
    print("=" * 60)
    print(" Linux Persistence Auditor  (read-only)")
    print("=" * 60)
    print(f" Home directory: {HOME}\n")

    total = 0
    warnings = 0

    for category, patterns in LOCATIONS.items():
        paths = resolve(patterns)
        print(f"[{category}]")
        if not paths:
            print("    (none found)")
        for path in paths:
            line = describe(path)
            if "WORLD-WRITABLE" in line:
                warnings += 1
            print(line)
            total += 1
        print()

    print("=" * 60)
    print(f" Reviewed {total} item(s). Flagged {warnings} world-writable item(s).")
    print(" Review each entry above and confirm it is expected on this host.")
    print("=" * 60)


if __name__ == "__main__":
    main()
