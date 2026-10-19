# Bastion — Desktop Security Suite

**By King Sabatsu Kisuke**  
**Status:** Personal cybersecurity learning project; actively being improved.

Bastion is a Python desktop application built with Tkinter to explore defensive security concepts by implementing the components directly rather than relying only on third-party security products. It combines heuristic firewall scoring, simulated intrusion-detection events, network inspection utilities, file encryption, CVE lookups, and local SQLite persistence in one interface.

> **Important:** Bastion is an educational project, not a production firewall, endpoint detection platform, or replacement for established security controls. Its presence of a feature in the interface does not imply that it has been independently security-tested.

## Features

- **Heuristic firewall engine:** IP threat scores, score decay, CIDR/TTL rules, allow/deny rules, and behavioural counters. The “AI” label refers to adaptive heuristic logic, not a trained machine-learning model.
- **Intrusion detection:** Signature matching over a sliding time window, with severity levels and event counters.
- **Attack sandbox:** Generates simulated events for exercising Bastion's own detection logic. It is not a general-purpose attack platform and does not demonstrate detection of all real network traffic.
- **Port inspection and process termination:** Checks selected TCP ports and can terminate a local process associated with a listening port. Terminating a process is not the same as closing a port with a firewall rule; use this feature carefully.
- **Vulnerability checks:** A set of basic checks intended for learning and authorized assessment, not a substitute for a maintained professional scanner.
- **Password and hash utilities:** Password-strength heuristics and hash-related exercises. Do not use a demonstration cracker as a guarantee that a password is secure.
- **Encryption vault:** Uses the Python `cryptography` package, including Fernet and PBKDF2-based key derivation, for text and file workflows. Review the limitations below before relying on it for important data.
- **CVE lookup:** Queries the NIST National Vulnerability Database (NVD), with local caching and optional API-key configuration.
- **Network device mapper:** Performs user-directed network discovery and provides shortcuts to other assessment views.
- **IP geolocation and globe view:** Uses a third-party geolocation service for approximate public-IP location data. Geolocation is not precise enough to identify a person's exact location.
- **Settings and activity history:** Stores application settings, firewall state, activity records, and caches in SQLite.

## Technology

- Python 3.10+
- Tkinter (included with most standard Windows Python installations)
- SQLite (Python standard library)
- `cryptography`
- `psutil` (optional process information and termination support)
- `requests` (optional online API lookups)
- PyInstaller (Windows executable packaging)

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or later
- Internet access for NVD and geolocation lookups
- Administrator privileges may be required for some local process/network operations

## Run from source

Open PowerShell in the project directory and run:

```powershell
py -m pip install -r requirements.txt
py bastion_v4.py
```

If the `py` launcher is unavailable, use `python` instead.

## Build a Windows executable

1. Open the project folder on Windows.
2. Double-click `build_exe.bat`.
3. The output should be created in `dist\Bastion.exe`.

For troubleshooting, use `build_exe_debug.bat` and read the console output. PyInstaller builds for the operating system on which it is run; build the Windows executable on Windows.

The app currently opens its SQLite database using a relative path (`bastion.db`). Its exact location therefore depends on the working directory from which the app is launched. Back up the database before testing or removing it.

## Security and implementation limitations

Please read these points before using Bastion beyond a learning environment:

1. **Not a production firewall:** The application’s firewall engine scores events it receives. It does not install a Windows Filtering Platform driver or automatically filter all operating-system network traffic.
2. **Heuristic “AI”:** The adaptive firewall is rule- and score-based logic, not a trained AI/ML model.
3. **Sandbox scope:** The attack sandbox simulates events to test Bastion’s own logic; it is not proof of detection against live attacks.
4. **Encryption needs further hardening:** The current implementation derives a Fernet key from a password using PBKDF2 and a fixed salt. A fixed salt is not the preferred design for new password-encryption formats. The file workflow also reads file contents into memory, so it should not be described as streaming encryption and may use substantial memory for large files. Do not rely on this version as the sole protection for irreplaceable or sensitive files. Changing the format safely requires a versioned format and backward-compatibility plan.
5. **Process termination is disruptive:** The port utility may stop a process that other software depends on. Confirm the process and PID before approving termination.
6. **Third-party services:** NVD and the geolocation provider are external services. Requests may fail, be rate-limited, or return approximate/stale information.
7. **Testing status:** Syntax compilation has been checked; this does not establish that every feature works correctly. Run the app and test each workflow on a machine you control before describing it as fully tested.

## Authorized use

Use scanning and process-management functions only on devices and networks you own or are explicitly authorized to assess. Avoid scanning public targets without written permission. Do not use this application as your only security control.

## Repository contents

- `bastion_v4.py` — application source
- `requirements.txt` — runtime dependencies
- `build_exe.bat` — windowed executable build
- `build_exe_debug.bat` — console-enabled debug build
- `.gitignore` — excludes local databases, caches, and build output

## License

No license is included in this repository. Unless a license is added, others should not assume they have permission to reuse, modify, or redistribute the source. Add an explicit license only after deciding whether you want this project to be open source or reserved for your own commercial use.
