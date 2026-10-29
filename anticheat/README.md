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

Options (file mode only): `-SkipProcessExplorer`, `-SkipHistory`, `-NoElevate`.

Output is results only: one line per check, the flagged items under it, then the safety score.

## Step 1 - System check

| Check | Result |
|---|---|
| CPU, GPU | info |
| OS is Windows (and not Wine) | fail if not |
| Virtual machine (BIOS/model/board, ACPI tables, display + disk models, guest tools, hypervisor MACs) | fail on strong indicators, yellow on weak ones |
| Defender: service, AV, antispyware, real-time, on-access, behaviour, IOAV, network inspection, tamper protection, cloud, signature age, disabling policies | fail (yellow when a third-party AV has replaced Defender) |
| Defender exclusions (Get-MpPreference + both registry locations) and ASR exclusions | fail / yellow |
| Running programs are not checked here. Staff review them in Process Explorer (Step 2). | - |
| Prefetch history and AppData folders for known cheat names | yellow |
| Running kernel drivers: unsigned or known cheat/mapper drivers | yellow |
| PowerShell integrity: genuine signed host, signed engine, core cmdlets not overridden, profiles, AMSI working | fail / yellow |
| Test signing, disabled driver signature checks, kernel debugging | fail |
| Secure Boot, firewall, hosts file entries for Roblox/Microsoft | yellow |

Then it prints a **safety score out of 100**: green for 90+ with no red, yellow for 70-89, red below 70.

The AMSI check runs Microsoft's harmless "AMSI test sample", so Windows Security may show a notification about it. That is expected.

## Step 2 - Process Explorer

After Step 1 the player presses Enter. The script downloads `procexp64.exe` (or the ARM64/x86 build) from `live.sysinternals.com` into a temporary folder, checks it has a valid Microsoft signature and launches it. Nothing is installed. When Process Explorer is closed, the temporary copy is deleted.

## Step 3 - Execution history and tampering

After Process Explorer is closed, the player presses Enter. This step looks back 7 days (`HistoryDays` in `$Config`):

| Check | Result |
|---|---|
| Programs run, from the Background Activity Moderator (`bam`) registry, including other user accounts. Only flagged ones are listed: known cheat/tool/macro names, executables **deleted after running**, and unsigned executables run from Temp/Downloads/Desktop and similar. | yellow per program, green if none |
| Microsoft Defender detections (threat name, time, file) | yellow per detection |
| Security log cleared (event 1102), other logs cleared (event 104) | red |
| Recycle Bin last changed and item count | info |

This step runs after the safety score, so it does not change it.

## Live monitor (`LiveMonitor.ps1`)

The live monitor is a separate script:

```powershell
iex (iwr "https://raw.githubusercontent.com/logicaltechpro-star/portfolio/claude/roblox-anticheat-ps1-l8naw6/anticheat/LiveMonitor.ps1" -UseBasicParsing).Content
```

It relaunches itself as administrator the same way as the main check. It prints one line per event with the time, event, PID and path:

| Event | Colour |
|---|---|
| `FILE CREATED` / `FILE DELETED` / `FILE RENAMED` in Temp, Windows\Temp, Prefetch, Downloads, Desktop, Recent, Recycle Bin, Roblox logs. The process that made the change is shown next to the path. | yellow for Prefetch, Recycle Bin, Roblox logs and `.exe .dll .sys .bat .cmd .ps1 .vbs .lua .luau .ahk`, otherwise grey |
| `PROCESS OPENED` (with parent) / `PROCESS CLOSED` | yellow for flagged names or unsigned executables, otherwise grey |
| `DRIVER LOADED` | red for flagged or unsigned drivers, otherwise yellow |
| `CAPTURE HIDDEN` / `CAPTURE SHOWN`: windows using `WDA_EXCLUDEFROMCAPTURE` or `WDA_MONITOR`, checked every 2 seconds | red / yellow |

As administrator on 64-bit Windows, the monitor uses the Windows Kernel-File and Kernel-Process event tracing (ETW) providers. This gives the PID for file events and catches processes that only run for a moment. Without that, it falls back to folder watchers and WMI. In that mode file events show `-` for PID and drivers are not reported, and a yellow line at the top says so.

The ETW session is called `AntiCheatLiveMonitor`. Staff stop the monitor with Ctrl+C, which also stops the session. If the window is closed with the X instead, the session keeps running until the next time the monitor starts (it stops any old session first) or until `logman stop AntiCheatLiveMonitor -ets` is run.

## Tuning

The flagged process names, window titles, folders, drivers and VM indicators are in the `$Config` block at the top of each script. Scoring weights are the numbers passed to `Write-Result`, and the per-category caps are in `$script:PenaltyCaps`.
