<#
.SYNOPSIS
    Community Anti-Cheat PC Check.

.DESCRIPTION
    Step 1 - System check
        Hardware (CPU / GPU), operating system, virtual machine detection,
        Microsoft Defender status, Defender exclusions (cmdlet + registry),
        PowerShell integrity, boot/kernel
        integrity and other indicators, followed by a safety score out of 100.

    Step 2 - Process Explorer (Sysinternals)
        Downloaded to a temporary folder (nothing is installed), its Microsoft
        signature is verified, it is launched for staff review and the
        temporary copy is removed once it is closed.

    Step 3 - Execution history and tampering
        Programs run in the last days (Background Activity Moderator registry),
        including ones deleted since, Microsoft Defender detections, cleared
        event logs and the last Recycle Bin change.

    The live monitor is a separate script: LiveMonitor.ps1.

    Colour key:
        GREEN  [PASS]  check passed
        YELLOW [WARN]  flagged for staff review
        RED    [FAIL]  check failed
        CYAN   [INFO]  information only

.EXAMPLE
    irm https://raw.githubusercontent.com/logicaltechpro-star/portfolio/claude/roblox-anticheat-ps1-l8naw6/anticheat/AntiCheatCheck.ps1 | iex
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\AntiCheatCheck.ps1
#>
[CmdletBinding()]
param(
    # Do not try to relaunch as administrator (some checks will be limited).
    [switch]$NoElevate,
    # Skip Step 2.
    [switch]$SkipProcessExplorer,
    # Skip Step 3.
    [switch]$SkipHistory
)

# =============================================================================
#  Configuration - edit these lists to tune what gets flagged
# =============================================================================
$Config = @{
    ScriptVersion = '1.0.0'

    # Executable base names (no .exe, case-insensitive). Matches are shown in
    # YELLOW for staff review, never red.
    FlaggedNames = [ordered]@{
        'Executor / injector' = @(
            'synapse', 'synapsex', 'synapse x', 'krnl', 'krnlss', 'fluxus', 'scriptware',
            'script-ware', 'electron', 'oxygenu', 'oxygen u', 'jjsploit', 'comet', 'trigon',
            'evon', 'valyse', 'solara', 'wave', 'celery', 'xeno', 'awp', 'seliware', 'nezur',
            'swift', 'sirhurt', 'calamari', 'sentinel', 'protosmasher', 'zenith', 'volcano',
            'velocity'
        )
        'Cheat / reversing tool' = @(
            'cheatengine', 'cheatengine-x86_64', 'cheatengine-x86_64-sse4-avx2', 'cheatengine-i386',
            'processhacker', 'systeminformer', 'x64dbg', 'x32dbg', 'x96dbg', 'ollydbg', 'ida', 'ida64',
            'dnspy', 'reclass', 'reclass.net', 'reclassex', 'extremeinjector', 'extreme injector v3',
            'xenos', 'xenos64', 'ghinjector', 'gh injector', 'kdmapper', 'ksdumper', 'scylla',
            'scylla_x64', 'httpdebuggerui', 'httpdebuggersvc'
        )
        'Macro / auto-clicker' = @(
            'autohotkey', 'autohotkey64', 'autohotkeyu64', 'autohotkeyu32', 'autohotkeyux',
            'autoclicker', 'opautoclicker', 'gs auto clicker', 'tinytask', 'macrorecorder'
        )
        'Remote access' = @(
            'teamviewer', 'teamviewer_service', 'anydesk', 'rustdesk', 'parsecd', 'remoting_host'
        )
    }

    # Folder names directly under %APPDATA% / %LOCALAPPDATA% that are flagged.
    FlaggedFolders = @(
        'Solara', 'krnl', 'Fluxus', 'Celery', 'Xeno', 'Synapse X', 'Seliware', 'Nezur',
        'Zenith', 'Volcano', 'Velocity', 'Script-Ware', 'JJSploit', 'Wave'
    )

    # Kernel driver base names that are flagged.
    FlaggedDrivers = @('dbk64', 'dbk32', 'capcom', 'kprocesshacker', 'kprocesshacker2', 'kprocesshacker3', 'ksysteminformer', 'iqvw64e', 'gdrv')

    # Vendor strings that indicate a virtual machine.
    VmVendorPattern = 'VMware|VirtualBox|VBOX|innotek|QEMU|KVM|Xen|Parallels|Bochs|BHYVE|Virtual Machine|Hyper-V|Red Hat|Proxmox|Amazon EC2|Google Compute'

    # Guest-tools services / processes that only run inside a virtual machine.
    VmServices  = @('VBoxService', 'VBoxGuest', 'VBoxSF', 'VBoxMouse', 'VMTools', 'vm3dservice', 'vmhgfs', 'VGAuthService', 'QEMU-GA', 'QEMU Guest Agent', 'prl_tools', 'xenservice', 'xensvc')
    VmProcesses = @('vmtoolsd', 'vmwaretray', 'vmwareuser', 'vboxservice', 'vboxtray', 'qemu-ga', 'prl_cc', 'prl_tools', 'xenservice', 'vmsrvc', 'vmusrvc')

    # MAC address prefixes registered to hypervisor vendors.
    VmMacPrefixes = @('00:05:69', '00:0C:29', '00:1C:14', '00:50:56', '08:00:27', '0A:00:27', '00:15:5D', '00:1C:42', '00:16:3E', '52:54:00')

    # Where this script is hosted. Used to relaunch as administrator when it
    # was started with "irm ... | iex" (there is no file to relaunch).
    ScriptUrl = 'https://raw.githubusercontent.com/logicaltechpro-star/portfolio/claude/roblox-anticheat-ps1-l8naw6/anticheat/AntiCheatCheck.ps1'

    # Executables in these locations are treated as higher risk when unsigned (regex).
    SuspiciousLocationPattern = '\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Downloads\\|\\Desktop\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|\\ProgramData\\[^\\]+\.exe$'

    # How far back Step 3 looks, in days.
    HistoryDays = 7

    # Sysinternals live download location for Step 2.
    SysinternalsLive = 'https://live.sysinternals.com'

}

# =============================================================================
#  Output helpers
# =============================================================================
$script:Results         = New-Object System.Collections.Generic.List[object]
$script:CategoryPenalty = @{}
# Maximum points a single category can remove from the score.
$script:PenaltyCaps     = @{
    Defender        = 40
    Prefetch        = 15
    Folders         = 10
    Drivers         = 20
}
$script:SigCache        = @{}
$script:ThirdPartyAv    = @()
$script:FinalScore      = $null

function Write-Result {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Check,
        [string]$Detail = '',
        [int]$Penalty = 0,
        [string]$Category = 'General'
    )
    $colour = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Status]
    Write-Host "[$Status] " -ForegroundColor $colour -NoNewline
    if ($Status -eq 'INFO') { Write-Host $Check -ForegroundColor White -NoNewline }
    else { Write-Host $Check -ForegroundColor $colour -NoNewline }
    if ($Detail -and $Status -ne 'PASS') { Write-Host " - $Detail" -ForegroundColor Gray } else { Write-Host '' }

    $applied = 0
    if ($Status -eq 'WARN' -or $Status -eq 'FAIL') {
        $applied = $Penalty
        if ($script:PenaltyCaps.ContainsKey($Category)) {
            $used    = [int]$script:CategoryPenalty[$Category]
            $applied = [Math]::Max(0, [Math]::Min($Penalty, $script:PenaltyCaps[$Category] - $used))
        }
        $script:CategoryPenalty[$Category] = [int]$script:CategoryPenalty[$Category] + $applied
    }
    $script:Results.Add([pscustomobject]@{
        Status = $Status; Check = $Check; Detail = $Detail; Penalty = $applied; Category = $Category
    })
}

# Indented detail line under a result (e.g. each flagged item).
function Write-Item([string]$Text, [string]$Colour = 'Gray') {
    Write-Host "       - $Text" -ForegroundColor $Colour
}

# =============================================================================
#  General helpers
# =============================================================================
function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FileSignature([string]$Path) {
    if (-not $Path) { return $null }
    $key = $Path.ToLowerInvariant()
    if (-not $script:SigCache.ContainsKey($key)) {
        $sig = $null
        try { $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop } catch { }
        $script:SigCache[$key] = $sig
    }
    $script:SigCache[$key]
}

function Get-SignerName($Signature) {
    if ($Signature -and $Signature.SignerCertificate) {
        if ($Signature.SignerCertificate.Subject -match 'CN="?([^",]+)') { return $Matches[1] }
        return $Signature.SignerCertificate.Subject
    }
    'no signer'
}

function Get-FlaggedCategory([string]$BaseName) {
    $name = $BaseName.ToLowerInvariant()
    foreach ($category in $Config.FlaggedNames.Keys) {
        if ($Config.FlaggedNames[$category] -contains $name) { return $category }
    }
    $null
}

# =============================================================================
#  Step 1 - System check
# =============================================================================
function Test-OperatingSystem {
    $isWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    if (-not $isWindows) {
        Write-Result FAIL 'Operating system is Windows' ("Detected: {0}" -f [Environment]::OSVersion.VersionString) 100
        return $false
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Write-Result PASS 'Operating system is Windows' ('{0} (build {1}, {2})' -f $os.Caption.Trim(), $os.BuildNumber, $os.OSArchitecture)
    }
    catch {
        Write-Result PASS 'Operating system is Windows' ([Environment]::OSVersion.VersionString)
    }

    # Windows API layer on Linux/macOS.
    if (Test-Path 'HKLM:\SOFTWARE\Wine') {
        Write-Result FAIL 'Not running under Wine' 'Wine registry key found' 40
    }
    $true
}

function Test-Hardware {
    try {
        foreach ($cpu in @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)) {
            Write-Result INFO 'CPU' ('{0} ({1} cores / {2} threads)' -f $cpu.Name.Trim(), $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors)
        }
    }
    catch { Write-Result WARN 'CPU' 'Could not query the processor' 2 }

    try {
        foreach ($gpu in @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop)) {
            Write-Result INFO 'GPU' ('{0} (driver {1})' -f $gpu.Name, $gpu.DriverVersion)
        }
    }
    catch { Write-Result WARN 'GPU' 'Could not query the graphics adapter' 2 }
}

function Test-VirtualMachine {
    $strong  = New-Object System.Collections.Generic.List[string]
    $weak    = New-Object System.Collections.Generic.List[string]
    $pattern = $Config.VmVendorPattern

    try {
        $cs    = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios  = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $board = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
        $fields = [ordered]@{
            'System manufacturer' = $cs.Manufacturer
            'System model'        = $cs.Model
            'BIOS manufacturer'   = $bios.Manufacturer
            'BIOS version'        = ((@($bios.BIOSVersion) + $bios.SMBIOSBIOSVersion) -join ' ')
            'BIOS serial'         = $bios.SerialNumber
            'Baseboard'           = if ($board) { "$($board.Manufacturer) $($board.Product)" } else { '' }
        }
        foreach ($key in $fields.Keys) {
            if ("$($fields[$key])" -match $pattern) { $strong.Add("$key = $($fields[$key])") }
        }
    }
    catch { $weak.Add('Could not read system/BIOS information') }

    # ACPI table names left by hypervisors.
    try {
        foreach ($table in @(Get-ChildItem 'HKLM:\HARDWARE\ACPI\DSDT' -ErrorAction Stop)) {
            if ($table.PSChildName -match 'VBOX|BOCHS|QEMU|XEN|PRLS|BHYVE|VRTUAL') { $strong.Add("ACPI table = $($table.PSChildName)") }
        }
    }
    catch { }

    try {
        foreach ($gpu in @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop)) {
            if ($gpu.Name -match "$pattern|SVGA|QXL|VirtIO") { $strong.Add("Display adapter = $($gpu.Name)") }
            elseif ($gpu.Name -match 'Basic Display Adapter') { $weak.Add("Display adapter = $($gpu.Name) (no GPU driver)") }
        }
    }
    catch { }

    try {
        foreach ($disk in @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop)) {
            if ($disk.Model -match $pattern) { $strong.Add("Disk = $($disk.Model)") }
            elseif ($disk.Model -match 'Virtual') { $weak.Add("Disk = $($disk.Model) (may be a mounted VHD)") }
        }
    }
    catch { }

    foreach ($svc in @(Get-Service -Name $Config.VmServices -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })) {
        $strong.Add("Guest service running = $($svc.Name)")
    }
    foreach ($proc in @(Get-Process -Name $Config.VmProcesses -ErrorAction SilentlyContinue)) {
        $strong.Add("Guest process running = $($proc.ProcessName)")
    }

    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' -ErrorAction Stop
        foreach ($nic in @($adapters)) {
            if (-not $nic.MACAddress) { continue }
            # Host-side virtual switches (VMware/VirtualBox/Hyper-V on the host) are expected.
            if ($nic.Name -match 'Virtual|VMware|VirtualBox|Hyper-V|vEthernet|Loopback|TAP|Miniport') { continue }
            $prefix = $nic.MACAddress.Substring(0, 8).ToUpperInvariant()
            if ($Config.VmMacPrefixes -contains $prefix) { $weak.Add("Network adapter '$($nic.Name)' has hypervisor MAC $($nic.MACAddress)") }
        }
    }
    catch { }

    if ($strong.Count -gt 0) {
        Write-Result FAIL 'Not running in a virtual machine' 'Virtual machine indicators found' 40
        foreach ($i in ($strong + $weak)) { Write-Item $i Red }
    }
    elseif ($weak.Count -gt 0) {
        Write-Result WARN 'Not running in a virtual machine' 'Possible indicators - staff review' 10
        foreach ($i in $weak) { Write-Item $i Yellow }
    }
    else {
        Write-Result PASS 'Not running in a virtual machine'
    }
}

function Test-Defender {

    # Third-party antivirus registered with Windows Security Center.
    try {
        $products = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        $script:ThirdPartyAv = @($products | Where-Object {
                $_.displayName -notmatch 'Defender' -and (($_.productState -band 0xF000) -eq 0x1000)
            } | ForEach-Object { $_.displayName })
    }
    catch { }

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        Write-Result FAIL 'Defender status' 'Get-MpComputerStatus failed - Defender is removed, disabled or broken' 40 Defender
        return
    }

    $passive = "$($mp.AMRunningMode)" -match 'Passive'
    if ($passive) {
        if ($script:ThirdPartyAv.Count -gt 0) {
            Write-Result WARN 'Defender running mode' "$($mp.AMRunningMode) (replaced by $($script:ThirdPartyAv -join ', '))" 5 Defender
        }
        else {
            Write-Result FAIL 'Defender running mode' "$($mp.AMRunningMode) with no other antivirus active" 20 Defender
        }
    }
    elseif ($mp.AMRunningMode) {
        Write-Result PASS 'Defender running mode' "$($mp.AMRunningMode)"
    }

    $statuses = [ordered]@{
        'Antimalware service'          = $mp.AMServiceEnabled
        'Antivirus'                    = $mp.AntivirusEnabled
        'Antispyware'                  = $mp.AntispywareEnabled
        'Real-time protection'         = $mp.RealTimeProtectionEnabled
        'On-access protection'         = $mp.OnAccessProtectionEnabled
        'Behavior monitoring'          = $mp.BehaviorMonitorEnabled
        'Download/attachment scanning' = $mp.IoavProtectionEnabled
        'Network inspection'           = $mp.NISEnabled
        'Tamper protection'            = $mp.IsTamperProtected
    }
    foreach ($name in $statuses.Keys) {
        if ($statuses[$name] -eq $true) { Write-Result PASS $name 'Enabled' }
        elseif ($passive -and $script:ThirdPartyAv.Count -gt 0) { Write-Result WARN $name 'Disabled (third-party antivirus in use)' 2 Defender }
        else { Write-Result FAIL $name 'Disabled' 8 Defender }
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        if ($pref.MAPSReporting -eq 0) { Write-Result WARN 'Cloud-delivered protection' 'Disabled' 3 Defender }
        else { Write-Result PASS 'Cloud-delivered protection' 'Enabled' }
    }
    catch { }

    if ($mp.AntivirusSignatureAge -gt 7) {
        Write-Result WARN 'Security intelligence age' ("{0} days old (last updated {1:yyyy-MM-dd})" -f $mp.AntivirusSignatureAge, $mp.AntivirusSignatureLastUpdated) 3 Defender
    }
    else {
        Write-Result PASS 'Security intelligence age' ("{0} day(s) old" -f $mp.AntivirusSignatureAge)
    }

    # Group Policy / registry values commonly used to switch Defender off.
    $policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $policies = @(
        @{ Path = $policyRoot; Name = 'DisableAntiSpyware' },
        @{ Path = $policyRoot; Name = 'DisableAntiVirus' },
        @{ Path = "$policyRoot\Real-Time Protection"; Name = 'DisableRealtimeMonitoring' },
        @{ Path = "$policyRoot\Real-Time Protection"; Name = 'DisableBehaviorMonitoring' },
        @{ Path = "$policyRoot\Real-Time Protection"; Name = 'DisableOnAccessProtection' },
        @{ Path = "$policyRoot\Real-Time Protection"; Name = 'DisableIOAVProtection' },
        @{ Path = "$policyRoot\Real-Time Protection"; Name = 'DisableScanOnRealtimeEnable' },
        @{ Path = "$policyRoot\Spynet"; Name = 'SpynetReporting'; Bad = 0 }
    )
    $setPolicies = @()
    foreach ($p in $policies) {
        $value = (Get-ItemProperty -LiteralPath $p.Path -Name $p.Name -ErrorAction SilentlyContinue).($p.Name)
        if ($null -eq $value) { continue }
        $bad = if ($p.ContainsKey('Bad')) { $p.Bad } else { 1 }
        if ($value -eq $bad) { $setPolicies += "$($p.Path)\$($p.Name) = $value" }
    }
    if ($setPolicies.Count -gt 0) {
        Write-Result FAIL 'No Defender-disabling policies' "$($setPolicies.Count) found" 10 Defender
        foreach ($i in $setPolicies) { Write-Item $i Red }
    }
    else {
        Write-Result PASS 'No Defender-disabling policies'
    }
}

function Test-DefenderExclusions {
    $found      = New-Object System.Collections.Generic.List[string]
    $unreadable = New-Object System.Collections.Generic.List[string]
    $mpReadable = $false

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $mpReadable = $true
        foreach ($prop in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
            foreach ($v in @($pref.$prop)) {
                if (-not $v) { continue }
                if ("$v" -match '^N/A') { $mpReadable = $false; $unreadable.Add('Get-MpPreference (requires administrator)'); continue }
                $found.Add("[$prop] $v")
            }
        }
        $asr = @($pref.AttackSurfaceReductionOnlyExclusions | Where-Object { $_ -and "$_" -notmatch '^N/A' })
        if ($asr.Count -gt 0) {
            Write-Result WARN 'No attack surface reduction exclusions' "$($asr.Count) found" 5
            foreach ($a in $asr) { Write-Item $a Yellow }
        }
    }
    catch { $unreadable.Add('Get-MpPreference') }

    $roots = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions',
             'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
    foreach ($root in $roots) {
        foreach ($sub in 'Paths', 'Processes', 'Extensions', 'IpAddresses', 'TemporaryPaths') {
            $keyPath = Join-Path $root $sub
            if (-not (Test-Path -LiteralPath $keyPath)) { continue }
            try {
                $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
                foreach ($valueName in $key.GetValueNames()) {
                    if (-not $valueName) { continue }
                    $found.Add("[Registry $sub] $valueName")
                }
            }
            # Defender's own key is normally readable by SYSTEM only; Get-MpPreference covers it.
            catch { }
        }
    }

    $unique = @($found | Sort-Object -Unique)
    if ($unique.Count -gt 0) {
        Write-Result FAIL 'No Defender exclusions' "$($unique.Count) exclusion(s) found" 25 Exclusions
        foreach ($i in $unique) { Write-Item $i Red }
    }
    elseif (-not $mpReadable) {
        Write-Result WARN 'No Defender exclusions' 'Could not be verified' 10 Exclusions
        foreach ($i in ($unreadable | Sort-Object -Unique)) { Write-Item "Unreadable: $i" Yellow }
    }
    else {
        Write-Result PASS 'No Defender exclusions' 'None in Defender or the registry'
    }
}

function Test-Prefetch {
    $prefetch = Join-Path $env:SystemRoot 'Prefetch'
    try {
        $files = @(Get-ChildItem -LiteralPath $prefetch -Filter '*.pf' -ErrorAction Stop)
    }
    catch {
        Write-Result WARN 'Prefetch history' 'Could not be read (requires administrator)' 3 Prefetch
        return
    }
    if ($files.Count -eq 0) {
        Write-Result WARN 'Prefetch history' 'Prefetch folder is empty (disabled or recently cleared)' 5 Prefetch
        return
    }

    $hits = 0
    foreach ($file in $files) {
        # NAME.EXE-HASH.pf
        $exe  = $file.BaseName -replace '-[0-9A-F]{8}$', ''
        $base = [IO.Path]::GetFileNameWithoutExtension($exe)
        $category = Get-FlaggedCategory $base
        if ($category -and $category -ne 'Remote access') {
            $hits++
            Write-Result WARN "Previously run: $exe" ("{0}, last run {1:yyyy-MM-dd HH:mm}" -f $category, $file.LastWriteTime) 5 Prefetch
        }
    }
    if ($hits -eq 0) {
        Write-Result PASS 'No known cheat / tool executables in Prefetch' ("{0} entries, oldest {1:yyyy-MM-dd}" -f $files.Count, ($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime)
    }
}

function Test-Folders {
    $hits = 0
    foreach ($root in @($env:APPDATA, $env:LOCALAPPDATA) | Where-Object { $_ }) {
        foreach ($name in $Config.FlaggedFolders) {
            $dir = Join-Path $root $name
            if (Test-Path -LiteralPath $dir -PathType Container) {
                $hits++
                Write-Result WARN "Folder found: $dir" ("last modified {0:yyyy-MM-dd HH:mm}" -f (Get-Item -LiteralPath $dir).LastWriteTime) 3 Folders
            }
        }
    }
    if ($hits -eq 0) { Write-Result PASS 'No known cheat folders in AppData' }
}

function Test-Drivers {
    try {
        $drivers = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "State='Running'" -ErrorAction Stop)
    }
    catch {
        Write-Result WARN 'Kernel drivers' 'Could not be enumerated' 3 Drivers
        return
    }

    $issues = 0
    foreach ($d in $drivers) {
        $path = "$($d.PathName)".Trim('"')
        $path = $path -replace '^\\\?\?\\', ''
        $path = $path -replace '^\\SystemRoot', $env:SystemRoot
        $path = $path -replace '^(?i)System32', (Join-Path $env:SystemRoot 'System32')
        $base = [IO.Path]::GetFileNameWithoutExtension($path)

        if ($Config.FlaggedDrivers -contains $base.ToLowerInvariant() -or $Config.FlaggedDrivers -contains "$($d.Name)".ToLowerInvariant()) {
            $issues++
            Write-Result WARN "Flagged driver: $($d.Name)" $path 10 Drivers
            continue
        }
        if ($path -and (Test-Path -LiteralPath $path)) {
            $sig = Get-FileSignature $path
            if (-not $sig -or $sig.Status -ne 'Valid') {
                $issues++
                $status = if ($sig) { $sig.Status } else { 'Unreadable' }
                Write-Result WARN "Unsigned driver: $($d.Name)" "$path [$status]" 3 Drivers
            }
        }
    }
    if ($issues -eq 0) { Write-Result PASS 'Kernel drivers' "$($drivers.Count) running drivers, none flagged" }
}

function Test-PowerShellIntegrity {
    # The host executable must be Microsoft-signed.
    $hostPath = (Get-Process -Id $PID).Path
    $hostSig  = Get-FileSignature $hostPath
    if ($hostSig -and $hostSig.Status -eq 'Valid' -and (Get-SignerName $hostSig) -match 'Microsoft') {
        Write-Result PASS 'PowerShell host is genuine' "$hostPath (signed by $(Get-SignerName $hostSig))"
    }
    else {
        $status = if ($hostSig) { $hostSig.Status } else { 'Unreadable' }
        Write-Result FAIL 'PowerShell host is genuine' "$hostPath [$status]" 20
    }

    # The engine assembly must be signed.
    $engine    = [PSObject].Assembly.Location
    $engineSig = Get-FileSignature $engine
    if ($engineSig -and $engineSig.Status -eq 'Valid') {
        Write-Result PASS 'PowerShell engine is signed' $engine
    }
    elseif ($engine) {
        $status = if ($engineSig) { $engineSig.Status } else { 'Unreadable' }
        Write-Result WARN 'PowerShell engine is signed' "$engine [$status]" 5
    }

    # Cmdlets this script relies on must not be shadowed by aliases or functions.
    $critical = 'Get-Process', 'Get-CimInstance', 'Get-AuthenticodeSignature', 'Get-ChildItem', 'Get-Item',
                'Get-ItemProperty', 'Get-Service', 'Get-MpComputerStatus', 'Get-MpPreference', 'Test-Path',
                'Write-Host', 'Get-FileHash', 'Invoke-WebRequest', 'Start-Process', 'Where-Object', 'ForEach-Object'
    $trusted  = '^(Microsoft\.PowerShell\.(Management|Utility|Security|Core)|CimCmdlets|Defender|ConfigDefender|ConfigDefenderPerformance)$'
    $tampered = New-Object System.Collections.Generic.List[string]
    foreach ($name in $critical) {
        foreach ($cmd in @(Get-Command -Name $name -All -ErrorAction SilentlyContinue)) {
            $source = "$($cmd.Source)"
            if ($cmd.CommandType -eq 'Alias' -or $source -notmatch $trusted) {
                $tampered.Add("$name is a $($cmd.CommandType) from '$source'")
            }
        }
    }
    if ($tampered.Count -gt 0) {
        Write-Result FAIL 'Core commands are not overridden' "$($tampered.Count) override(s)" 20
        foreach ($t in $tampered) { Write-Item $t Red }
    }
    else {
        Write-Result PASS 'Core commands are not overridden'
    }

    # Profiles run before any script unless -NoProfile is used.
    $profiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) -and (Get-Item -LiteralPath $_).Length -gt 0 }
    if (@($profiles).Count -gt 0) {
        Write-Result WARN 'No PowerShell profiles' "$(@($profiles).Count) profile script(s) present" 2
        foreach ($p in $profiles) { Write-Item $p Yellow }
    }
    else {
        Write-Result PASS 'No PowerShell profiles'
    }

    # AMSI functional test using Microsoft's harmless AMSI test sample. The
    # string is assembled at runtime so this file itself is not detected.
    $sample = "'AMSI Test Sample: " + (@('7e72c3ce', '861b', '4339', '8740', '0ac1484f1386') -join '-') + "'"
    $blocked = $false
    try { $null = Invoke-Expression $sample -ErrorAction Stop }
    catch { $blocked = "$($_.FullyQualifiedErrorId)" -match 'ScriptContainedMaliciousContent' -or "$($_.Exception.Message)" -match 'malicious' }
    if ($blocked) {
        Write-Result PASS 'AMSI script scanning works' 'A Defender notice about "AMSI test sample" is expected'
    }
    elseif ($script:ThirdPartyAv.Count -gt 0) {
        Write-Result WARN 'AMSI script scanning works' 'Test sample not blocked (third-party antivirus may not use the test sample)' 5
    }
    else {
        Write-Result FAIL 'AMSI script scanning works' 'Test sample was NOT blocked - AMSI is bypassed or disabled' 20
    }
}

function Test-SystemIntegrity {

    # Options of the current boot (locale independent, unlike bcdedit output).
    $startOptions = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name SystemStartOptions -ErrorAction SilentlyContinue).SystemStartOptions
    $bootChecks = @(
        @{ Name = 'Test signing mode is off';         Pattern = '\bTESTSIGNING\b';              Penalty = 25 },
        @{ Name = 'Driver signature checks enforced'; Pattern = '\bDISABLE_INTEGRITY_CHECKS\b'; Penalty = 25 },
        @{ Name = 'Kernel debugging is off';          Pattern = '\bDEBUG\b';                  Penalty = 20 }
    )
    foreach ($b in $bootChecks) {
        if ("$startOptions" -match $b.Pattern) { Write-Result FAIL $b.Name "Boot options: $($startOptions.Trim())" $b.Penalty }
        else { Write-Result PASS $b.Name }
    }

    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) { Write-Result PASS 'Secure Boot' 'Enabled' }
        else { Write-Result WARN 'Secure Boot' 'Disabled' 3 }
    }
    catch { Write-Result WARN 'Secure Boot' 'Not supported or could not be read (legacy BIOS / not administrator)' 2 }

    try {
        $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled })
        if ($off.Count -gt 0) { Write-Result WARN 'Windows Firewall' "Disabled for: $(($off | ForEach-Object Name) -join ', ')" 3 }
        else { Write-Result PASS 'Windows Firewall' 'Enabled for all profiles' }
    }
    catch { }

    $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $entries = @(Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue |
        Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' -and $_ -match 'roblox|rbxcdn|microsoft|windowsupdate|defender|smartscreen' })
    if ($entries.Count -gt 0) {
        Write-Result WARN 'Hosts file' "$($entries.Count) entry(s) affecting Roblox/Microsoft domains" 5
        foreach ($e in $entries) { Write-Item $e.Trim() Yellow }
    }
    else {
        Write-Result PASS 'Hosts file' 'No entries affecting Roblox/Microsoft domains'
    }
}

function Show-SafetyScore {
    $penalty = ($script:Results | Measure-Object -Property Penalty -Sum).Sum
    $score   = [int][Math]::Max(0, [Math]::Min(100, 100 - $penalty))
    $fails   = @($script:Results | Where-Object Status -eq 'FAIL').Count

    if ($score -ge 90 -and $fails -eq 0) { $colour = 'Green' }
    elseif ($score -ge 70)               { $colour = 'Yellow' }
    else                                 { $colour = 'Red' }

    Write-Host ''
    Write-Host ("Safety Score: {0}/100" -f $score) -ForegroundColor $colour
    $script:FinalScore = $score
}

function Invoke-Step1SystemCheck {

    $script:FinalScore = $null
    if (-not (Test-OperatingSystem)) {
        Show-SafetyScore
        $script:FinalScore = $null
        return
    }

    if (Test-IsAdmin) { Write-Result PASS 'Running as administrator' }
    else { Write-Result WARN 'Running as administrator' 'Not elevated - some checks are limited' 10 }

    Test-Hardware
    Test-VirtualMachine
    Test-Defender
    Test-DefenderExclusions
    Test-Prefetch
    Test-Folders
    Test-Drivers
    Test-PowerShellIntegrity
    Test-SystemIntegrity

    Show-SafetyScore
}

# =============================================================================
#  Step 2 - Process Explorer
# =============================================================================
function Invoke-Step2ProcessExplorer {
    Write-Host ''

    $exe = switch ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { 'procexp64a.exe' }
        'AMD64' { 'procexp64.exe' }
        default { 'procexp.exe' }
    }
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ('procexp-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $target  = Join-Path $tempDir $exe
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        $oldProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri "$($Config.SysinternalsLive)/$exe" -OutFile $target -UseBasicParsing -ErrorAction Stop
        }
        catch {
            # Fallback: the Sysinternals Live WebDAV share.
            Copy-Item -LiteralPath "\\live.sysinternals.com\tools\$exe" -Destination $target -ErrorAction Stop
        }
        finally {
            $ProgressPreference = $oldProgress
        }

        $sig = Get-AuthenticodeSignature -LiteralPath $target
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            Write-Result FAIL 'Process Explorer' "Not a valid Microsoft signature [$($sig.Status)] - not launched"
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            return
        }
        $proc = Start-Process -FilePath $target -ArgumentList '/accepteula' -PassThru -ErrorAction Stop
        Write-Result PASS 'Process Explorer'
        $proc.WaitForExit()
        Start-Sleep -Milliseconds 500
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Result FAIL 'Process Explorer' "Could not download or start: $($_.Exception.Message)"
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =============================================================================
#  Step 3 - Execution history and tampering
# =============================================================================
$script:DosDeviceSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AntiCheat
{
    public static class DosDevice
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, int max);

        public static string Query(string deviceName)
        {
            StringBuilder target = new StringBuilder(1024);
            return QueryDosDeviceW(deviceName, target, target.Capacity) != 0 ? target.ToString() : null;
        }
    }
}
'@

# Maps \Device\HarddiskVolumeN\ prefixes to drive letters.
function Get-DeviceMap {
    $map = @{}
    if (-not ('AntiCheat.DosDevice' -as [type])) {
        try { Add-Type -TypeDefinition $script:DosDeviceSource -ErrorAction Stop } catch { return $map }
    }
    foreach ($drive in [IO.DriveInfo]::GetDrives()) {
        $letter = $drive.Name.Substring(0, 2)
        $device = [AntiCheat.DosDevice]::Query($letter)
        if ($device) { $map["$device\"] = "$letter\" }
    }
    $map
}

function Test-ExecutionHistory {
    $cutoff = (Get-Date).AddDays(-$Config.HistoryDays)
    $map    = Get-DeviceMap
    $roots  = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
              'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'

    # Background Activity Moderator: last run time per executable, per user.
    $entries = @{}
    $readable = $false
    foreach ($root in $roots) {
        foreach ($userKey in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $readable = $true
            foreach ($name in $userKey.GetValueNames()) {
                if ($name -notmatch '^\\Device\\') { continue }
                $data = $userKey.GetValue($name)
                if (-not ($data -is [byte[]]) -or $data.Length -lt 8) { continue }
                try { $time = [DateTime]::FromFileTime([BitConverter]::ToInt64($data, 0)) } catch { continue }
                if ($time -lt $cutoff) { continue }

                $path = $name
                foreach ($device in $map.Keys) {
                    if ($name.StartsWith($device, [StringComparison]::OrdinalIgnoreCase)) { $path = $map[$device] + $name.Substring($device.Length); break }
                }
                if (-not $entries.ContainsKey($path) -or $entries[$path] -lt $time) { $entries[$path] = $time }
            }
        }
    }

    if (-not $readable) {
        Write-Result WARN 'Execution history' 'Could not be read (requires administrator)'
        return
    }

    $flaggedCount = 0
    foreach ($path in ($entries.Keys | Sort-Object { $entries[$_] } -Descending)) {
        $reasons = @()
        $category = Get-FlaggedCategory ([IO.Path]::GetFileNameWithoutExtension($path))
        if ($category -and $category -ne 'Remote access') { $reasons += $category }

        $exists = [IO.Path]::IsPathRooted($path) -and (Test-Path -LiteralPath $path)
        if (-not $exists -and $path -notmatch '^\\Device\\') {
            $reasons += 'deleted after running'
        }
        elseif ($exists -and $path -match $Config.SuspiciousLocationPattern) {
            $sig = Get-FileSignature $path
            if (-not $sig -or $sig.Status -ne 'Valid') { $reasons += 'unsigned, ' + $(if ($sig) { "$($sig.Status)" } else { 'Unreadable' }) }
        }

        if ($reasons.Count -gt 0) {
            $flaggedCount++
            Write-Result WARN "Ran: $path" ("{0:yyyy-MM-dd HH:mm}, {1}" -f $entries[$path], ($reasons -join ', '))
        }
    }
    if ($flaggedCount -eq 0) {
        Write-Result PASS "Execution history ($($entries.Count) programs in $($Config.HistoryDays) days, none flagged)"
    }
}

function Test-DefenderHistory {
    $cutoff = (Get-Date).AddDays(-$Config.HistoryDays)
    try {
        $detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $cutoff })
    }
    catch {
        Write-Result WARN 'Defender detection history' 'Could not be read'
        return
    }
    if ($detections.Count -eq 0) {
        Write-Result PASS "No Defender detections in $($Config.HistoryDays) days"
        return
    }

    $names = @{}
    try { foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $names["$($t.ThreatID)"] = $t.ThreatName } } catch { }
    foreach ($d in ($detections | Sort-Object InitialDetectionTime -Descending)) {
        $name  = if ($names.ContainsKey("$($d.ThreatID)")) { $names["$($d.ThreatID)"] } else { "Threat ID $($d.ThreatID)" }
        $where = (@($d.Resources) | ForEach-Object { "$_" -replace '^\w+:_', '' }) -join ', '
        Write-Result WARN "Defender detection: $name" ("{0:yyyy-MM-dd HH:mm}, {1}" -f $d.InitialDetectionTime, $where)
    }
}

function Test-LogTampering {
    $cutoff = (Get-Date).AddDays(-$Config.HistoryDays)
    $checks = @(
        @{ Log = 'Security'; Id = 1102; Name = 'Security log' },
        @{ Log = 'System';   Id = 104;  Name = 'System/Application logs' }
    )
    foreach ($c in $checks) {
        try {
            $cleared = @(Get-WinEvent -FilterHashtable @{ LogName = $c.Log; Id = $c.Id; StartTime = $cutoff } -ErrorAction Stop)
            $latest  = $cleared | Sort-Object TimeCreated -Descending | Select-Object -First 1
            Write-Result FAIL "$($c.Name) not cleared" ("cleared {0} time(s), last {1:yyyy-MM-dd HH:mm}" -f $cleared.Count, $latest.TimeCreated)
        }
        catch {
            # Get-WinEvent throws when no events match.
            if ("$($_.FullyQualifiedErrorId)" -match 'NoMatchingEventsFound') { Write-Result PASS "$($c.Name) not cleared" }
            else { Write-Result WARN "$($c.Name) not cleared" 'Could not be read' }
        }
    }

    # The current user's Recycle Bin folder changes when files are deleted or it is emptied.
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $bin = Get-Item -LiteralPath (Join-Path $env:SystemDrive "`$Recycle.Bin\$sid") -Force -ErrorAction Stop
        $items = @(Get-ChildItem -LiteralPath $bin.FullName -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })
        Write-Result INFO 'Recycle Bin' ("last changed {0:yyyy-MM-dd HH:mm}, {1} item(s)" -f $bin.LastWriteTime, [Math]::Floor($items.Count / 2))
    }
    catch { }
}

function Invoke-Step3History {
    Write-Host ''
    Test-ExecutionHistory
    Test-DefenderHistory
    Test-LogTampering
}

# =============================================================================
#  Main
# =============================================================================
# Wrapped in a function so "return" ends the check without closing the
# player's PowerShell window when the script is run with "irm ... | iex".
function Invoke-AntiCheatCheck {
    $onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

    if ($onWindows -and -not $NoElevate -and -not (Test-IsAdmin)) {
        if ($PSCommandPath) {
            $argList = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
            if ($SkipProcessExplorer) { $argList += '-SkipProcessExplorer' }
            if ($SkipHistory)         { $argList += '-SkipHistory' }
        }
        else {
            # Started from memory via iex: download and run again in the elevated window.
            $command = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; iex (iwr '$($Config.ScriptUrl)' -UseBasicParsing).Content"
            $argList = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "`"$command`"")
        }
        try {
            Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argList -Verb RunAs -ErrorAction Stop
            return
        }
        catch { }
    }

    try { $Host.UI.RawUI.WindowTitle = 'Anti-Cheat PC Check' } catch { }
    Clear-Host

    Invoke-Step1SystemCheck | Out-Null
    if ($null -eq $script:FinalScore) { return }

    if (-not $SkipProcessExplorer) {
        Write-Host ''
        Read-Host 'Press Enter to continue to Step 2 (Process Explorer)' | Out-Null
        Invoke-Step2ProcessExplorer
    }

    if (-not $SkipHistory) {
        Write-Host ''
        Read-Host 'Press Enter to continue to Step 3 (Execution History)' | Out-Null
        Invoke-Step3History
    }
}

Invoke-AntiCheatCheck
