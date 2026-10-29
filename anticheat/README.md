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

Options (file mode only): `-SkipProcessExplorer`, `-SkipLiveMonitor`, `-NoElevate`.

Output is results only: one line per check, the flagged items under it, then the safety score.

## Step 1 - System check

| Check | Result |
|---|---|
| CPU, GPU | info |
| OS is Windows (and not Wine) | fail if not |
| Virtual machine (BIOS/model/board, ACPI tables, display + disk models, guest tools, hypervisor MACs) | fail on strong indicators, yellow on weak ones |
| Defender: service, AV, antispyware, real-time, on-access, behaviour, IOAV, network inspection, tamper protection, cloud, signature age, disabling policies | fail (yellow when a third-party AV has replaced Defender) |
| Defender exclusions (Get-MpPreference + both registry locations) and ASR exclusions | fail / yellow |
| Running processes: known executor/tool/macro/remote-access names, window titles, windows hidden from screen capture, unsigned or untrusted executables (more weight if in Temp/Downloads/Desktop) | yellow |
| Prefetch history and AppData folders for known cheat names | yellow |
| Running kernel drivers: unsigned or known cheat/mapper drivers | yellow |
| PowerShell integrity: genuine signed host, signed engine, core cmdlets not overridden, profiles, AMSI working | fail / yellow |
| Test signing, disabled driver signature checks, kernel debugging | fail |
| Secure Boot, firewall, hosts file entries for Roblox/Microsoft | yellow |

Then it prints a **safety score out of 100**: green for 90+ with no red, yellow for 70-89, red below 70.

The AMSI check runs Microsoft's harmless "AMSI test sample", so Windows Security may show a notification about it. That is expected.

## Step 2 - Process Explorer

After Step 1 the player presses Enter. The script downloads `procexp64.exe` (or the ARM64/x86 build) from `live.sysinternals.com` into a temporary folder, checks it has a valid Microsoft signature and launches it. Nothing is installed. The temporary copy is deleted when the live monitor stops.

## Step 3 - Live monitor

The player presses Enter again. The monitor then prints one line per event, with the time, event, PID and path, until Ctrl+C is pressed:

| Event | Source | Colour |
|---|---|---|
| `FILE CREATED` / `FILE DELETED` / `FILE RENAMED` | Temp, Windows\Temp, Prefetch, Downloads, Desktop, Recent, Recycle Bin | yellow for Prefetch, Recycle Bin and `.exe .dll .sys .bat .cmd .ps1 .vbs .lua .luau .ahk`, otherwise grey |
| `PROCESS OPENED` / `PROCESS CLOSED` | WMI process start/stop trace (polled every second if not admin) | yellow for flagged names or unsigned executables, otherwise grey |
| `CAPTURE HIDDEN` / `CAPTURE SHOWN` | Windows with `WDA_EXCLUDEFROMCAPTURE` or `WDA_MONITOR` display affinity, checked every 2 seconds | red / yellow |

Windows file notifications do not say which process made the change, so file events show `-` for PID.

Step 1 also reports any window that is already hidden from capture.

## Tuning

The flagged process names, window titles, folders, drivers and VM indicators are in the `$Config` block at the top of the script. Scoring weights are the numbers passed to `Write-Result`, and the per-category caps are in `$script:PenaltyCaps`.
