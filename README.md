# Linux Persistence Auditor

A read-only defensive tool that inventories common Linux persistence locations (cron, systemd units, shell startup files, autostart entries, boot scripts, SSH authorized keys) so a defender can review each entry for anything unexpected. It does not modify the system.

## Usage
```bash
python3 persistence_auditor.py
```

World-writable items are flagged. Review every entry and confirm it is expected on the host.
