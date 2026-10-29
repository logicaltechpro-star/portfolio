# Anti-Cheat PC Check

A PowerShell check that players run before a screenshare with staff.

Colour key: **green** `[PASS]` = pass, **yellow** `[WARN]` = flagged for staff review, **red** `[FAIL]` = fail, cyan `[INFO]` = information only.

## Running

Players paste this into PowerShell (no download or file needed):

```powershell
irm https://raw.githubusercontent.com/logicaltechpro-star/portfolio/claude/roblox-anticheat-ps1-l8naw6/anticheat/AntiCheatCheck.ps1 | iex
```

If the window is not elevated, the script opens a new administrator PowerShell window that downloads and runs the script again (from `ScriptUrl` in `$Config`). Update `ScriptUrl` and the command above if the script moves, for example to `main`. The repository must be public for this to work.

Running from a saved file also works:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\AntiCheatCheck.ps1
```

Options (file mode only): `-SkipProcessExplorer` (Step 1 only), `-NoElevate`, `-NoPause`.

## Step 1 - System check

| Check | Result |
|---|---|
| CPU, GPU, RAM, OS build, uptime | info |
| OS is Windows (and not Wine) | fail if not |
| Virtual machine (BIOS/model/board, ACPI tables, display + disk models, guest tools, hypervisor MACs) | fail on strong indicators, yellow on weak ones |
| Defender: service, AV, antispyware, real-time, on-access, behaviour, IOAV, network inspection, tamper protection, cloud, signature age, disabling policies | fail (yellow when a third-party AV has replaced Defender) |
| Defender exclusions (Get-MpPreference + both registry locations) and ASR exclusions | fail / yellow |
| Running processes: known executor/tool/macro/remote-access names, window titles, unsigned or untrusted executables (more weight if in Temp/Downloads/Desktop) | yellow |
| Prefetch history and AppData folders for known cheat names | yellow |
| Running kernel drivers: unsigned or known cheat/mapper drivers | yellow |
| PowerShell integrity: genuine signed host, signed engine, core cmdlets not overridden, profiles, AMSI working, script SHA256 | fail / yellow |
| Test signing, disabled driver signature checks, kernel debugging | fail |
| Secure Boot, firewall, hosts file entries for Roblox/Microsoft | yellow |

Then it prints a **safety score out of 100** (90+ and no red = SAFE, 70-89 = REVIEW, below 70 = UNSAFE), lists where points were lost, and saves a report to the Desktop.

The AMSI check runs Microsoft's harmless "AMSI test sample", so Windows Security may show a notification about it. That is expected.

## Step 2 - Process Explorer

Downloads `procexp64.exe` (or the ARM64/x86 build) from `live.sysinternals.com` into a temporary folder. It checks for a valid Microsoft signature, launches it, waits for it to be closed and then deletes the temporary copy. Nothing is installed.

## Tuning

The flagged process names, window titles, folders, drivers and VM indicators are in the `$Config` block at the top of the script. Scoring weights are the numbers passed to `Write-Result`, and the per-category caps are in `$script:PenaltyCaps`.

Publish the script's SHA256 (shown in Step 1) so staff can confirm a player ran the unmodified version.
