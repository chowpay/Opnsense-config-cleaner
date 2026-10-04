# OPNsense Config Cleaner

A small Windows GUI utility for sanitizing OPNsense configuration XML exports before sharing them for troubleshooting or review.

The app is written in Python and uses Tkinter for the desktop GUI.

## What it does

The cleaner preserves the useful OPNsense configuration while blanking known sensitive credential fields such as:

- Passwords
- API keys
- Private keys
- Tokens
- SNMP community strings
- Dynamic DNS usernames/passwords
- Proxy/authentication credentials
- GeoIP URL secrets
- SSH authorized keys
- OTP seeds

There is also an option to strip audit-history usernames/IPs.

> Note: A sanitized file is not fully anonymous. Network details such as hostnames, IP addresses, MAC addresses, DHCP reservations, firewall rules, VLANs, and service configuration may still be present so the file remains useful for troubleshooting.

## Run from Python

From the project directory:

```powershell
python .\opn_config_cleaner.py
```

If you are using the project's virtual environment in PyCharm, make sure it is active first.

## Build the Windows EXE

### 1. Install PyInstaller

From the project directory with the virtual environment active:

```powershell
python -m pip install pyinstaller
```

### 2. Build the executable

```powershell
pyinstaller --onefile --windowed --name "OPNsense-Config-Cleaner" .\opn_config_cleaner.py
```

PyInstaller will create build files and place the finished executable here:

```text
dist\OPNsense-Config-Cleaner.exe
```

The `build\`, `dist\`, and `*.spec` files are ignored by Git in this project.

### 3. Test the executable

Run:

```powershell
.\dist\OPNsense-Config-Cleaner.exe
```

You can also close PyCharm and double-click the EXE in the `dist` folder to confirm it works as a standalone Windows application.

## Rebuilding after code changes

The EXE is a packaged snapshot of the Python code at build time.

If you change `opn_config_cleaner.py`, test the Python version first:

```powershell
python .\opn_config_cleaner.py
```

When you are ready to distribute a new version, run the PyInstaller build command again:

```powershell
pyinstaller --onefile --windowed --name "OPNsense-Config-Cleaner" .\opn_config_cleaner.py
```

The newly built EXE will be placed in:

```text
dist\OPNsense-Config-Cleaner.exe
```

## Git workflow

Typical development workflow:

```powershell
git add .
git commit -m "Describe the change"
git push
```

The compiled EXE is normally not committed directly to the repository. A cleaner approach is to keep source code in Git and publish finished EXE builds through GitHub Releases.

## Safety

Always keep the original OPNsense export unchanged.

The cleaner writes a separate sanitized copy and should never overwrite the original configuration file.

Before publicly sharing a sanitized configuration, review it for environment-specific information you may also want to remove, such as:

- Internal IP addresses
- Hostnames
- MAC addresses
- Device descriptions
- Domain names
- Network topology details

## Project files

```text
opn_config_cleaner.py
.gitignore
README.md
```

After building locally, you may also see:

```text
build\
dist\
OPNsense-Config-Cleaner.spec
```
