
# --- INIT FIXES ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not $log) { $log = New-Object System.Collections.Generic.List[string] }
if (-not $flags) { $flags = 0 }

# ==============================================================================
#   SUB'S RECORDING POLICY 
#   
# ==============================================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$webhookUrl = "https://discord.com/api/webhooks/1492882358125199371/zaFJcZ94jZCXTaDehvGfa8elwZtJOLSdUtGtWzjpH3FqBABWaYuao_O9H4uzS3c9_mQp"
$logPath    = "$env:TEMP\Subrecresult.txt"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "CRITICAL ERROR: Administrator privileges required." -ForegroundColor Red
    Pause; exit 1
}

Clear-Host
Write-Host "=== Sub's Recording Policy - System Integrity Audit v5.0 ===" -ForegroundColor Cyan
Write-Host "Scan in progress. This may take several minutes."              -ForegroundColor White
Write-Host ""

$script:ScanPercent = 0
function Update-ScanProgress {
    param(
        [int]$Percent
    )

    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    if ($Percent -lt $script:ScanPercent) { $Percent = $script:ScanPercent }

    $script:ScanPercent = $Percent
    Write-Host "$Percent%"
}

Update-ScanProgress -Percent 1


# --- CACHES & MATCHERS ---
$script:CachedProcesses = $null
$script:CachedProcessesWithUser = $null
$script:CachedServices = $null
$script:CimCache = @{}

function Get-ProcessSnapshot {
    if ($null -eq $script:CachedProcesses) {
        $script:CachedProcesses = @(Get-Process -ErrorAction SilentlyContinue)
    }
    return $script:CachedProcesses
}

function Get-ProcessSnapshotWithUser {
    if ($null -eq $script:CachedProcessesWithUser) {
        $script:CachedProcessesWithUser = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue)
    }
    return $script:CachedProcessesWithUser
}

function Get-ServiceSnapshot {
    if ($null -eq $script:CachedServices) {
        $script:CachedServices = @(Get-Service -ErrorAction SilentlyContinue)
    }
    return $script:CachedServices
}

function Get-CachedCimInstance {
    param(
        [string]$ClassName,
        [string]$Namespace = ""
    )
    $cacheKey = if ([string]::IsNullOrWhiteSpace($Namespace)) { $ClassName } else { "$Namespace|$ClassName" }
    if (-not $script:CimCache.ContainsKey($cacheKey)) {
        $result = if ([string]::IsNullOrWhiteSpace($Namespace)) {
            @(Get-CimInstance -ClassName $ClassName -ErrorAction SilentlyContinue)
        } else {
            @(Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction SilentlyContinue)
        }
        $script:CimCache[$cacheKey] = $result
    }
    return $script:CimCache[$cacheKey]
}
$log.Add("======================================================")
$log.Add("   Sub's Recording Policy | $(Get-Date)   ")
$log.Add("======================================================")


# ==============================================================================
#   SECTION: DEVICE INFO & SPECIFICATIONS
# ==============================================================================
Update-ScanProgress -Percent 3  
$log.Add("`n[SECTION: DEVICE INFO & SPECIFICATIONS]")

try {
    $cs    = (Get-CachedCimInstance "Win32_ComputerSystem" | Select-Object -First 1)
    $os    = (Get-CachedCimInstance "Win32_OperatingSystem" | Select-Object -First 1)
    $cpu   = (Get-CachedCimInstance "Win32_Processor" | Select-Object -First 1)
    $gpus  = Get-CachedCimInstance "Win32_VideoController"
    $disks = Get-CachedCimInstance "Win32_DiskDrive"
    $bios  = (Get-CachedCimInstance "Win32_BIOS" | Select-Object -First 1)

    $ramGB     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $freeRamGB = [math]::Round($os.FreePhysicalMemory  / 1MB, 2)

    $log.Add("PC Name       : $($cs.Name)")
    $log.Add("User          : $($env:USERNAME)")
    $log.Add("Domain        : $($cs.Domain)")
    $log.Add("OS            : $($os.Caption) $($os.OSArchitecture) (Build $($os.BuildNumber))")
    $log.Add("OS Version    : $($os.Version)")
    $log.Add("CPU           : $($cpu.Name) | Cores: $($cpu.NumberOfCores) | Threads: $($cpu.NumberOfLogicalProcessors)")
    $log.Add("RAM           : $ramGB GB total | $freeRamGB GB free")
    $log.Add("Manufacturer  : $($cs.Manufacturer) $($cs.Model)")
    $log.Add("BIOS          : $($bios.Manufacturer) v$($bios.SMBIOSBIOSVersion) | Serial: $($bios.SerialNumber)")

    foreach ($gpu in $gpus) {
        $log.Add("GPU           : $($gpu.Name) | VRAM: $([math]::Round($gpu.AdapterRAM / 1GB, 2)) GB | Driver: $($gpu.DriverVersion)")
    }
    foreach ($disk in $disks) {
        $log.Add("Disk          : $($disk.Model) | Size: $([math]::Round($disk.Size / 1GB, 2)) GB | Interface: $($disk.InterfaceType)")
    }

    $uptime = (Get-Date) - $os.LastBootUpTime
    $log.Add("Uptime        : $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m")
    $log.Add("Scan Time     : $(Get-Date)")
} catch {
    $log.Add("WARNING: Could not retrieve full device info.")
}


# ==============================================================================
#   HELPER FUNCTIONS
# ==============================================================================

function Check-RegistryClean {
    param ([string]$Path, [string]$Name, [switch]$StrictDefaultOnly)
    if (Test-Path $Path) {
        try {
            $item   = Get-Item $Path
            $values = $item.GetValueNames()
            if ($StrictDefaultOnly) {
                if ($values.Count -le 1 -and ($values -contains "" -or $values.Count -eq 0)) {
                    $log.Add("PASS: $Name is clean.")
                } else {
                    foreach ($v in $values) {
                        if ($v -ne "") { $log.Add("FAIL: $Name has unexpected value -> $v"); $script:flags++ }
                    }
                }
            } else {
                foreach ($v in $values) {
                    if ($v -ne "") { $log.Add("INFO: $Name -> $v") }
                }
            }
        } catch { $log.Add("WARNING: Could not access $Name") }
    } else { $log.Add("INFO: $Name not present.") }
}

function Scan-RegistryTree {
    param ([string]$BasePath, [string]$Label)
    if (Test-Path $BasePath) {
        $allKeys  = @(Get-Item $BasePath)
        $allKeys += Get-ChildItem -Path $BasePath -Recurse -ErrorAction SilentlyContinue
        foreach ($key in $allKeys) {
            try {
                foreach ($v in $key.GetValueNames()) {
                    if ($v -ne "") { $log.Add("FAIL: $Label -> Value '$v' in $($key.Name)"); $script:flags++ }
                }
                foreach ($sk in (Get-ChildItem $key.PSPath -ErrorAction SilentlyContinue)) {
                    $log.Add("FAIL: $Label -> Subkey detected: $($sk.PSChildName)"); $script:flags++
                }
            } catch {}
        }
    } else { $log.Add("PASS: $Label not present.") }
}


# ==============================================================================
#   SECTION: REGISTRY INTEGRITY
# ==============================================================================
Update-ScanProgress -Percent 8  
$log.Add("`n[SECTION: REGISTRY INTEGRITY]")

Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"                      "Windows Config Key"
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" "Image File Execution Options"
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction"         "Defender Threat Actions"       -StrictDefaultOnly
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"                 "Defender Exclusion Extensions" -StrictDefaultOnly

$extendedIntegrityKeys = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"                              = "Defender Policy Override"
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"                     = "Winlogon (Persistence Risk)"
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"            = "Silent Process Exit Injection"
    "HKCU:\Software\Classes\ms-settings"                                              = "UAC Bypass (ms-settings)"
    "HKCU:\Software\Classes\mscfile\shell\open\command"                               = "UAC Bypass (mscfile)"
    "HKCU:\Software\Classes\exefile\shell\runas\command"                              = "UAC Bypass (exefile runas)"
    "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal"                         = "Safe Boot Minimal (Rootkit Risk)"
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"                                      = "LSA Configuration"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" = "Browser Helper Objects (Injection Risk)"
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"        = "AppCompat Custom Flags"
}

foreach ($entry in $extendedIntegrityKeys.GetEnumerator()) {
    Check-RegistryClean $entry.Key $entry.Value
}


# ==============================================================================
#   SECTION: TASKBAR & STARTUP AUDIT
# ==============================================================================
Update-ScanProgress -Percent 12 
$log.Add("`n[SECTION: TASKBAR & STARTUP AUDIT]")

try {
    foreach ($p in (Get-ProcessSnapshot | Where-Object { $_.MainWindowTitle -ne "" })) {
        $log.Add("TASKBAR: $($p.ProcessName) | Window: $($p.MainWindowTitle)")
    }
} catch { $log.Add("INFO: Could not enumerate taskbar windows.") }

try {
    foreach ($path in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $path) {
            (Get-ItemProperty -Path $path).PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $log.Add("STARTUP: $($_.Name) -> $($_.Value)")
            }
        }
    }
} catch { $log.Add("INFO: Could not enumerate startup items.") }

try {
    if (Test-Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify") {
        $log.Add("INFO: Tray notification cache present.")
    }
} catch {}

foreach ($bp in (Get-ProcessSnapshot | Where-Object { $_.MainWindowHandle -eq 0 -and $_.ProcessName -notmatch "svchost|System|Idle" })) {
    $log.Add("BACKGROUND: $($bp.ProcessName)")
}


# ==============================================================================
#   SECTION: SYSTEM CONFIGURATION VALIDATION
# ==============================================================================
Update-ScanProgress -Percent 16 
$log.Add("`n[SECTION: SYSTEM CONFIGURATION VALIDATION]")
$configIssues = $false

try {
    $scheme = (Get-ItemProperty "HKCU:\Control Panel\Cursors" -Name Scheme -ErrorAction SilentlyContinue).Scheme
    if ([string]::IsNullOrWhiteSpace($scheme) -or $scheme -like "*Windows Default*") {
        $log.Add("PASS: Mouse pointer scheme is default.")
    } else {
        $log.Add("FAIL: Mouse pointer scheme is modified ($scheme).")
        $configIssues = $true
    }
} catch { $log.Add("INFO: Could not verify mouse pointer scheme.") }

try {
    $visualFX = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -ErrorAction SilentlyContinue).VisualFXSetting
    if ($visualFX -eq 1) {
        $log.Add("PASS: Visual effects set to best appearance.")
    } else {
        $log.Add("FAIL: Visual effects not set to best appearance (Value: $visualFX).")
        $configIssues = $true
    }
} catch { $log.Add("INFO: Could not verify visual effects setting.") }

try {
    $uacKey       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $consent      = (Get-ItemProperty $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $promptSecure = (Get-ItemProperty $uacKey -Name PromptOnSecureDesktop      -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    $enableLua    = (Get-ItemProperty $uacKey -Name EnableLUA                  -ErrorAction SilentlyContinue).EnableLUA
    if ($enableLua -eq 1 -and $consent -eq 5 -and $promptSecure -eq 0) {
        $log.Add("PASS: UAC level is correct.")
    } else {
        $log.Add("FAIL: UAC level incorrect (Consent: $consent | SecureDesktop: $promptSecure | LUA: $enableLua).")
        $configIssues = $true
    }
} catch { $log.Add("INFO: Could not verify UAC settings.") }

if ($configIssues) {
    $log.Add("FAIL: System configuration requirements not met.")
    Write-Host "`n[!] Fix the following issues before continuing:" -ForegroundColor Red
    Write-Host "    - Reset mouse pointers to Windows Default"                           -ForegroundColor Yellow
    Write-Host "    - Set visual effects to Best Appearance"                             -ForegroundColor Yellow
    Write-Host "    - Set UAC to: Notify me only when apps try to make changes (no dim)" -ForegroundColor Yellow
    Write-Host "`nRerun the audit once resolved." -ForegroundColor Cyan
    Pause; exit 1
} else {
    $log.Add("PASS: All system configuration checks passed.")
}


# ==============================================================================
#   SECTION: CORE ISOLATION & MEMORY PROTECTION
# ==============================================================================
Update-ScanProgress -Percent 20  
$log.Add("`n[SECTION: CORE ISOLATION & MEMORY PROTECTION]")

try {
    $hvciKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $hvciVal = (Get-ItemProperty $hvciKey -Name Enabled -ErrorAction SilentlyContinue).Enabled
    if ($hvciVal -eq 1) {
        $log.Add("PASS: Memory Integrity (HVCI) is enabled.")
    } else {
        $log.Add("FAIL: Memory Integrity (HVCI) is disabled or not configured (Value: $hvciVal).")
        $flags++
    }
} catch { $log.Add("INFO: Could not verify Memory Integrity status.") }

try {
    $vdbKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
    $vdbVal = (Get-ItemProperty $vdbKey -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
    if ($vdbVal -eq 1) {
        $log.Add("PASS: Vulnerable Driver Blocklist is enabled.")
    } else {
        $log.Add("FAIL: Vulnerable Driver Blocklist is disabled or not configured (Value: $vdbVal).")
        $flags++
    }
} catch { $log.Add("INFO: Could not verify Vulnerable Driver Blocklist status.") }

try {
    $vbsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $vbsVal = (Get-ItemProperty $vbsKey -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    if ($vbsVal -eq 1) {
        $log.Add("PASS: Virtualization Based Security (VBS) is enabled.")
    } else {
        $log.Add("WARN: Virtualization Based Security (VBS) is disabled (Value: $vbsVal).")
    }
} catch { $log.Add("INFO: Could not verify VBS status.") }


# ==============================================================================
#   SECTION: HYPERVISOR DETECTION (TYPE 1 & TYPE 2)
# ==============================================================================
Update-ScanProgress -Percent 24 
$log.Add("`n[SECTION: HYPERVISOR DETECTION]")
$hvFound = $false

try {
    $cs = (Get-CachedCimInstance "Win32_ComputerSystem" | Select-Object -First 1)
    if ($cs.HypervisorPresent) {
        $log.Add("WARN: HypervisorPresent flag is True — a Type 1 hypervisor may be active.")
        $hvFound = $true; $flags++
    }
} catch {}

try {
    $bcdedit = & "$env:SystemRoot\System32\bcdedit.exe" /enum ALL 2>$null | Out-String
    if ($bcdedit -imatch "hypervisorlaunchtype\s+Auto") {
        $log.Add("FAIL: Hyper-V set to launch automatically (Type 1 hypervisor active)."); $flags++; $hvFound = $true
    }
} catch {}

foreach ($hk in @("HKLM:\SYSTEM\CurrentControlSet\Services\IntelHaxm","HKLM:\SYSTEM\CurrentControlSet\Services\HAXMDriver")) {
    if (Test-Path $hk) { $log.Add("FAIL: Intel HAXM hypervisor component found -> $hk"); $flags++; $hvFound = $true }
}

try {
    $whpx = Get-Service -Name "WHvProvider" -ErrorAction SilentlyContinue
    if ($whpx -and $whpx.Status -eq "Running") {
        $log.Add("FAIL: Windows Hypervisor Platform (WHPX) is running."); $flags++; $hvFound = $true
    }
} catch {}

foreach ($proc in (Get-ProcessSnapshot)) {
    foreach ($hp in @("vmware-vmx","vmwaretray","vmwareuser","VirtualBox","VBoxHeadless","VBoxManage","VBoxSVC","vboxservice","vboxtray")) {
        if ($proc.ProcessName -ilike "*$hp*") {
            $log.Add("FAIL: Type 2 hypervisor process -> $($proc.ProcessName)"); $flags++; $hvFound = $true
        }
    }
}

try {
    foreach ($svc in (Get-ServiceSnapshot)) {
        foreach ($hs in @("VBoxDrv","VBoxNetAdp","VBoxNetFlt","VBoxUSBMon","vmci","vmhgfs","vmmouse","vsepflt","VBoxSF","vmvss")) {
            if ($svc.Name -ilike "*$hs*") {
                $log.Add("FAIL: Type 2 hypervisor service -> $($svc.Name) [$($svc.Status)]"); $flags++; $hvFound = $true
            }
        }
    }
} catch {}

foreach ($rk in @("HKLM:\SOFTWARE\Oracle\VirtualBox","HKLM:\SOFTWARE\VMware, Inc.\VMware Tools","HKLM:\SYSTEM\CurrentControlSet\Services\VBoxDrv","HKLM:\SYSTEM\CurrentControlSet\Services\vmci","HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters")) {
    if (Test-Path $rk) { $log.Add("FAIL: Hypervisor registry key present -> $rk"); $flags++; $hvFound = $true }
}

try {
    foreach ($drv in (Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        foreach ($kw in @("vboxdrv","vmhgfs","vmci","vsepflt","hvix64","hvax64","VBoxNetFlt","IntelHaxm","winhvr")) {
            if ($drv.Name -ilike "*$kw*" -or $drv.PathName -ilike "*$kw*") {
                $log.Add("FAIL: Hypervisor kernel driver -> $($drv.Name) | $($drv.PathName)"); $flags++; $hvFound = $true
            }
        }
    }
} catch {}

# BIOS/DMI strings
try {
    $bios    = (Get-CachedCimInstance "Win32_BIOS" | Select-Object -First 1)
    $board   = Get-CachedCimInstance "Win32_BaseBoard"
    $comp    = (Get-CachedCimInstance "Win32_ComputerSystem" | Select-Object -First 1)
    $sysInfo = "$($bios.SerialNumber) $($bios.Version) $($bios.SMBIOSBIOSVersion) $($bios.Manufacturer) $($board.Manufacturer) $($board.Product) $($comp.Manufacturer) $($comp.Model)"
    $biosHit = $false
    foreach ($vs in @("VBOX","VIRTUALBOX","VMWARE","QEMU","XEN","KVM","BHYVE","BOCHS","PARALLELS","INNOTEK","VIRT","HYPERV","PROXMOX")) {
        if ($sysInfo -ilike "*$vs*") {
            $log.Add("FAIL: VM/Hypervisor BIOS string [$vs] -> $sysInfo"); $flags++; $hvFound = $true; $biosHit = $true
        }
    }
    if (-not $biosHit) { $log.Add("PASS: BIOS/DMI strings appear physical.") }
} catch {}

# MAC OUI
try {
    $macHit = $false
    foreach ($nic in ((Get-CachedCimInstance "Win32_NetworkAdapterConfiguration") | Where-Object { $_.MACAddress })) {
        $oui = ($nic.MACAddress -replace ":","").ToUpper().Substring(0,6)
        if (@("000C29","005056","001C14","000569","080027","00155D","525400","00163E","001C42","0003FF") -contains $oui) {
            $log.Add("FAIL: Virtual adapter MAC OUI -> $($nic.Description) | $($nic.MACAddress)"); $flags++; $hvFound = $true; $macHit = $true
        }
    }
    if (-not $macHit) { $log.Add("PASS: No virtual adapter MAC addresses detected.") }
} catch {}

# CPU string
try {
    $cpuInst  = (Get-CachedCimInstance "Win32_Processor" | Select-Object -First 1)
    $cpuStr   = "$($cpuInst.Name) $($cpuInst.Description)"
    $cpuHit   = $false
    foreach ($vs in @("Virtual","QEMU","KVM","VMware","VirtualBox","Hyper-V","Xen","Bochs","Parallels")) {
        if ($cpuStr -ilike "*$vs*") {
            $log.Add("FAIL: VM CPU string detected [$vs] -> $cpuStr"); $flags++; $hvFound = $true; $cpuHit = $true
        }
    }
    if (-not $cpuHit) { $log.Add("PASS: CPU brand string appears physical.") }
} catch {}

# Virtual disk
try {
    $diskHit = $false
    foreach ($disk in (Get-CachedCimInstance "Win32_DiskDrive")) {
        $diskStr = "$($disk.Model) $($disk.Caption) $($disk.PNPDeviceID)"
        foreach ($vs in @("VBOX","VMWARE","QEMU","VIRTUAL","MSFT VIRTUAL","HYPERV SCSI","XENSRC","NVME VIRTUAL")) {
            if ($diskStr -ilike "*$vs*") {
                $log.Add("FAIL: Virtual disk detected [$vs] -> $($disk.Model)"); $flags++; $hvFound = $true; $diskHit = $true
            }
        }
    }
    if (-not $diskHit) { $log.Add("PASS: No virtual disk signatures detected.") }
} catch {}

# Virtual GPU
try {
    $gpuHit = $false
    foreach ($gpu in (Get-CachedCimInstance "Win32_VideoController")) {
        $gpuStr = "$($gpu.Name) $($gpu.Description)"
        foreach ($vs in @("VirtualBox","VMware","SVGA","Virtual Display","Hyper-V Video","QEMU","Parallels","Basic Display","Standard VGA")) {
            if ($gpuStr -ilike "*$vs*") {
                $log.Add("FAIL: Virtual GPU detected [$vs] -> $($gpu.Name)"); $flags++; $hvFound = $true; $gpuHit = $true
            }
        }
    }
    if (-not $gpuHit) { $log.Add("PASS: No virtual GPU signatures detected.") }
} catch {}

# Sandboxie / WSL
try {
    $sandboxHit = $false
    foreach ($svc in (Get-ServiceSnapshot)) {
        if ($svc.Name -ilike "*Sbie*" -or $svc.Name -ilike "*sandboxie*") {
            $log.Add("FAIL: Sandboxie service detected -> $($svc.Name) [$($svc.Status)]"); $flags++; $hvFound = $true; $sandboxHit = $true
        }
    }
    $wslSvc = Get-Service -Name "LxssManager" -ErrorAction SilentlyContinue
    if ($wslSvc -and $wslSvc.Status -eq "Running") {
        $log.Add("WARN: WSL (Linux Subsystem) is currently running.")
    }
    if (-not $sandboxHit) { $log.Add("PASS: No Sandboxie indicators found.") }
} catch {}

# Hypervisor DLLs outside normal space
$normalDllRoots = @("$env:SystemRoot\system32","$env:SystemRoot\syswow64","$env:SystemRoot\winsxs","$env:SystemRoot\microsoft.net",$env:ProgramFiles,${env:ProgramFiles(x86)}) |
    ForEach-Object { if ($_) { $_.ToLower() } }

foreach ($proc in (Get-ProcessSnapshot)) {
    try {
        foreach ($m in $proc.Modules) {
            $pathLow = $m.FileName.ToLower()
            $isNormal = ($normalDllRoots | Where-Object { $_ -and $pathLow.StartsWith($_) }).Count -gt 0
            if (-not $isNormal) {
                foreach ($kw in @("vbox","vmware","vmci","xen","qemu","bochs","parallels","intelHaxm","winhvr")) {
                    if ($pathLow -like "*$kw*") {
                        $log.Add("FAIL: Hypervisor DLL outside system space in [$($proc.ProcessName)] -> $($m.FileName)"); $flags++; $hvFound = $true
                    }
                }
            }
        }
    } catch {}
}

if (-not $hvFound) { $log.Add("PASS: No hypervisor indicators detected.") }


# ==============================================================================
#   SECTION 1: HARDWARE & DISPLAY
# ==============================================================================
$log.Add("`n[SECTION 1: HARDWARE]")
$displays     = Get-CachedCimInstance "WmiMonitorBasicDisplayParams" "root\wmi" | Where-Object { $_.Active }
$displayCount = ($displays | Measure-Object).Count
$log.Add("Active Displays: $displayCount $(if($displayCount -eq 1){'(PASS)'}else{'(FAIL)'})")


# ==============================================================================
#   MASTER CHEAT BLACKLIST  (v5 — crypt removed, crypt-bypass retained)
# ==============================================================================
$cheatBlacklist = @(
    # Roblox Executors
    "matcha","olduimatrix","autoexe","monkeyaim","thunderaim","thunderclient","celex","matrix",
    "triggerbot","solara","xeno","wave","cloudy","tupical","horizon","myst","celery","zarora",
    "juju","nezure","FusionHacks","aimmy","Fluxus","clumsy","MystW","isabelle","dx9ware",
    "synapse","krnl","sentinel","sirhurt","skisploit","comet","oxygen","nihon",
    "evon","vega","delta","arceus","hydrogen","codex","valyse","fluctus","incognito",
    "scriptware","sw-m","ro-exec","krampus","macsploit",
    "trigon","jjsploit","wearedevs","hydroxide","darkdex","infiniteyield",
    "calamari","remotespy","proxo","furk","speedhub",
    "nighthub","hohohub","wally","zephyr","dansploit","penguinware",
    "fluxteam","elysian","cocoz","silenttrigger","rblxware","crypt-bypass",
    "rbxcheat","rbxexploit","xhub","sw-x","yoru","blade",
    "ronin","sirius","deathware","kadefi","oxide","fulcrumware","uncap",
    "excalibur","raindrop","bleu","lunar","galactic","temple","elixir",
    "carbon","catware","kiriot","rxploit","rexploit","topkek","rise",
    "zenith","netless","xray","ether","typhoon","abyss","eclipse",
    "nitro","cyclone","impulse","exodus","aurora","prism","vertex","inferno",
    "alchemy","ghostware","skript","oxsuite",
    "hyperion bypass","byfron bypass","noclip","studio injector",
    "swan","kaito","kurokage","darkrift",
    # Cheat Engine & Memory Tools
    "cheatengine","cheat engine","dbk64","dbk32","speedhack",
    "processhacker","hollows hunter","moneta","pe-sieve",
    "artmoney","tsearch","memhack","memoryhacker","scanmem",
    # DMA / Kernel Tools
    "pcileech","kdmapper","dmacheck","fpga","squirrel","lambdaconcept",
    "screamer","enigma","komodo","pcimem","rweverything","rw-everything",
    "MemProcFS","dma_read","dma_write","dma_tool",
    # Generic Cheat Indicators
    "injector","cheat","hack","esp","aimbot","exploit","executor","softaim","d3d9.dll",
    "vape","phantom","killaura","usermode","internal","external","bypass","loader",
    "spoofer","hwid","silent","fov","recoil","nospread","wallhack",
    "bhop","bunnyhop","autofire","rapidfire","norecoil","noflash",
    "aimassist","aimlock","spinbot","autoaim","autoclick","autoclicker",
    "keyauth","keygen","patcher","cracker","dumper","reflectiveloader",
    # Macro / Input Automation
    "autohotkey","tinytask","jitbit","xmouse","xdotool","macrorecorder","itaskbar"
)

$cheatExactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($term in $cheatBlacklist) {
    $normalized = $term.Trim().ToLower()
    if (-not [string]::IsNullOrWhiteSpace($normalized)) { [void]$cheatExactSet.Add($normalized) }
}
$cheatRegex = [regex]::new((($cheatBlacklist | Sort-Object Length -Descending | ForEach-Object { [regex]::Escape($_) }) -join '|'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$suspiciousIndicatorRegex = [regex]::new('roblox.{0,16}(cheat|executor|exploit|hack|inject|bypass)|\b(injector|executor|loader|dll injector|manual map|reflective loader|reflectiveloader|hook|softaim|aimbot|silent ?aim|triggerbot|wallhack|esp|speedhack|bypass|spoofer|hwid|macro|autoclick|keyauth|patcher|cracker|dumper|scanmem|memoryhacker|processhacker|pe-sieve|moneta|remotespy|darkdex|infiniteyield)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Test-BlacklistTerm {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $candidate = $Text.ToLower()
    if ($cheatExactSet.Contains($candidate)) { return $true }
    return $cheatRegex.IsMatch($candidate)
}

function Test-SuspiciousIndicator {
    param(
        [string]$Text,
        [switch]$BlacklistOnly
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    if (Test-BlacklistTerm $Text) { return $true }
    if ($BlacklistOnly) { return $false }

    $lower = $Text.ToLower()
    foreach ($token in ($lower -split '[^a-z0-9\-\._]+')) {
        if (-not [string]::IsNullOrWhiteSpace($token) -and $cheatExactSet.Contains($token)) {
            return $true
        }
    }
    return $suspiciousIndicatorRegex.IsMatch($lower)
}


# --- HIGH-SIGNAL HELPERS ---
$script:AllowedSignerRegex = [regex]::new('(microsoft|roblox|nvidia|advanced micro devices|amd|intel|corsair|logitech|razer|steelseries|discord|obs project|valve|epic games|google|mozilla)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$script:ProtectedTargetRegex = [regex]::new('(RobloxPlayerBeta|RobloxPlayerInstaller|RobloxStudioBeta|dwm|explorer)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Test-UserWritablePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $candidates = @(
        $env:TEMP,
        $env:TMP,
        $env:APPDATA,
        $env:LOCALAPPDATA,
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Documents')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($root in $candidates) {
        try {
            if ($Path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        } catch {}
    }
    return $false
}

function Get-FileSignatureInfo {
    param([string]$Path)
    $status = 'Unknown'; $signer = ''
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) {
        return [PSCustomObject]@{ Status=$status; Signer=$signer; Allowed=$false }
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        if ($sig) {
            $status = [string]$sig.Status
            try { $signer = [string]$sig.SignerCertificate.Subject } catch { $signer = '' }
        }
    } catch {}
    $allowed = $false
    if ($status -eq 'Valid' -and -not [string]::IsNullOrWhiteSpace($signer) -and $script:AllowedSignerRegex.IsMatch($signer)) { $allowed = $true }
    [PSCustomObject]@{ Status=$status; Signer=$signer; Allowed=$allowed }
}

function Test-ProtectedTarget {
    param([string]$ImagePathOrName)
    if ([string]::IsNullOrWhiteSpace($ImagePathOrName)) { return $false }
    return $script:ProtectedTargetRegex.IsMatch($ImagePathOrName)
}

function Get-EventMessageField {
    param([string]$Message,[string]$Name)
    if ([string]::IsNullOrWhiteSpace($Message) -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    foreach ($line in ($Message -split "`r?`n")) {
        if ($line -match ('^' + [regex]::Escape($Name) + '\s*:\s*(.*)$')) { return $Matches[1].Trim() }
    }
    return $null
}


function Test-KnownBenignDllPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return $Path -match '(discord|google\\chrome|chrome\\application|microsoft\\edge|edge\\application|mozilla\\firefox|bravesoftware|opera software|opera gx|steam|riot games|epic games|ubisoft|battle\.net|nvidia|amd|intel|obs-studio|medal|streamlabs|spotify|onedrive|teams|slack|zoom|notion|gitkraken|postman|curseforge|overwolf)'
}

function Convert-DevicePathToDrivePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ($Path -match '^\\Device\\HarddiskVolume\d+\\(.+)$') {
        return "C:\$($matches[1])"
    }
    return $Path
}

function Get-SafeBamTime {
    param([byte[]]$Data)
    if ($null -eq $Data -or $Data.Length -lt 8) { return $null }
    try {
        $fileTime = [BitConverter]::ToInt64($Data, 0)
        if ($fileTime -le 0) { return $null }
        $maxFileTime = [DateTime]::MaxValue.ToFileTimeUtc()
        if ($fileTime -ge $maxFileTime) { return $null }
        $dt = [DateTime]::FromFileTimeUtc($fileTime)
        if ($dt.Year -lt 2000 -or $dt.Year -gt 2100) { return $null }
        return $dt.ToLocalTime()
    } catch {
        return $null
    }
}


# ==============================================================================
#   SECTION 2: FILESYSTEM FORENSICS
# ==============================================================================
$log.Add("`n[SECTION 2: FILESYSTEM FORENSICS]")

try {
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    if ($pfFiles) {
        $log.Add("Total Prefetch Files: $($pfFiles.Count)")
        foreach ($pf in $pfFiles | Sort-Object LastWriteTime -Descending) {
            $exeName = ($pf.BaseName -split "-")[0]
            $log.Add("PREFETCH: $exeName | Last Run: $($pf.LastWriteTime)")
            if (Test-BlacklistTerm $exeName) { $log.Add("FLAGGED: Suspicious prefetch entry -> $exeName"); $flags++ }
        }
    } else { $log.Add("WARNING: Prefetch directory is empty or inaccessible.") }
} catch { $log.Add("FAIL: Prefetch scan error.") }

try {
    if (Test-Path "C:\ProgramData\KeyAuth\debug") {
        foreach ($f in (Get-ChildItem "C:\ProgramData\KeyAuth\debug" -Directory)) {
            $log.Add("FAIL: KeyAuth debug folder detected -> $($f.FullName)"); $flags++
        }
    } else { $log.Add("PASS: No KeyAuth debug folders found.") }
} catch {}


# ==============================================================================
#   SECTION 3: ROBLOX BOOTSTRAPPER AUDIT
# ==============================================================================
$log.Add("`n[SECTION 3: ROBLOX BOOTSTRAPPER AUDIT]")

$bootstrapPaths = @(
    @{ Name = "Bloxstrap"; Path = "$env:LOCALAPPDATA\Bloxstrap\Settings.json" },
    @{ Name = "Fishstrap"; Path = "$env:LOCALAPPDATA\Fishstrap" },
    @{ Name = "Voidstrap"; Path = "$env:LOCALAPPDATA\Voidstrap" },
    @{ Name = "Plexity";   Path = "$env:LOCALAPPDATA\Plexity" },
    @{ Name = "Velostrap"; Path = "$env:LOCALAPPDATA\Velostrap" }
)

$bootstrapDetected = $false
foreach ($b in $bootstrapPaths) {
    if (Test-Path $b.Path) {
        $bootstrapDetected = $true
        $log.Add("DETECTED: Bootstrapper -> $($b.Name)")
        if ($b.Name -eq "Bloxstrap" -and $b.Path -like "*.json") {
            try {
                $settings = Get-Content $b.Path -Raw | ConvertFrom-Json
                if ($null -eq $settings.CustomIntegrations -or $settings.CustomIntegrations.Count -eq 0) {
                    $log.Add("PASS: Bloxstrap has no custom integrations.")
                } else {
                    foreach ($ci in $settings.CustomIntegrations) {
                        $log.Add("FAIL: Bloxstrap integration -> $($ci.Name) | $($ci.Location)"); $flags++
                    }
                }
            } catch { $log.Add("WARNING: Bloxstrap config could not be read.") }
        } else {
            try {
                foreach ($f in (Get-ChildItem $b.Path -Recurse -ErrorAction SilentlyContinue)) {
                    if (Test-BlacklistTerm $f.Name) { $log.Add("FAIL: Suspicious file in $($b.Name) -> $($f.FullName)"); $flags++ }
                }
            } catch {}
        }
    }
}
if (-not $bootstrapDetected) { $log.Add("PASS: No known Roblox bootstrappers detected.") }


# ==============================================================================
#   SECTION 3B: EXECUTOR KNOWN INSTALLATION PATHS
# ==============================================================================
$log.Add("`n[SECTION 3B: EXECUTOR KNOWN PATHS]")

$executorPaths = @(
    @{ Name = "Synapse X";        Path = "$env:APPDATA\SynapseX"               },
    @{ Name = "Synapse X (alt)";  Path = "$env:APPDATA\Synapse"                },
    @{ Name = "KRNL";             Path = "$env:LOCALAPPDATA\KRNL"              },
    @{ Name = "Scriptware";       Path = "$env:LOCALAPPDATA\Scriptware"        },
    @{ Name = "Fluxus";           Path = "$env:LOCALAPPDATA\Fluxus"            },
    @{ Name = "Fluxus (appdata)"; Path = "$env:APPDATA\Fluxus"                },
    @{ Name = "Solara";           Path = "$env:APPDATA\Solara"                 },
    @{ Name = "Solara (local)";   Path = "$env:LOCALAPPDATA\Solara"            },
    @{ Name = "Wave";             Path = "$env:LOCALAPPDATA\Wave"              },
    @{ Name = "Wave (appdata)";   Path = "$env:APPDATA\Wave"                  },
    @{ Name = "Celery";           Path = "$env:APPDATA\Celery"                 },
    @{ Name = "Celery (local)";   Path = "$env:LOCALAPPDATA\Celery"            },
    @{ Name = "Horizon";          Path = "$env:APPDATA\Horizon"                },
    @{ Name = "Evon";             Path = "$env:LOCALAPPDATA\Evon"              },
    @{ Name = "Delta";            Path = "$env:APPDATA\Delta"                  },
    @{ Name = "Delta (local)";    Path = "$env:LOCALAPPDATA\Delta"             },
    @{ Name = "Arceus X";         Path = "$env:LOCALAPPDATA\Arceus"            },
    @{ Name = "Hydrogen";         Path = "$env:APPDATA\Hydrogen"               },
    @{ Name = "Codex";            Path = "$env:APPDATA\Codex"                  },
    @{ Name = "Calamari";         Path = "$env:APPDATA\Calamari"               },
    @{ Name = "JJSploit";         Path = "$env:APPDATA\JJSploit"               },
    @{ Name = "WeAreDevs";        Path = "$env:LOCALAPPDATA\WeAreDevs"         },
    @{ Name = "Elysian";          Path = "$env:APPDATA\Elysian"                },
    @{ Name = "Xeno";             Path = "$env:APPDATA\Xeno"                   },
    @{ Name = "Trigon";           Path = "$env:APPDATA\Trigon"                 },
    @{ Name = "Oxygen U";         Path = "$env:APPDATA\OxygenU"                },
    @{ Name = "Nihon";            Path = "$env:APPDATA\Nihon"                  },
    @{ Name = "KeyAuth";          Path = "C:\ProgramData\KeyAuth"              },
    @{ Name = "Aimmy";            Path = "$env:APPDATA\Aimmy"                  },
    @{ Name = "Sirhurt";          Path = "$env:APPDATA\Sirhurt"                },
    @{ Name = "SkiSploit";        Path = "$env:APPDATA\SkiSploit"              },
    @{ Name = "Proxo";            Path = "$env:APPDATA\Proxo"                  },
    @{ Name = "SpeedHub";         Path = "$env:APPDATA\SpeedHub"               },
    @{ Name = "NightHub";         Path = "$env:APPDATA\NightHub"               },
    @{ Name = "HohoHub";          Path = "$env:APPDATA\HohoHub"                },
    @{ Name = "DX9Ware";          Path = "$env:APPDATA\dx9ware"                },
    @{ Name = "Matcha";           Path = "$env:APPDATA\Matcha"                 },
    @{ Name = "Ronin";            Path = "$env:APPDATA\Ronin"                  },
    @{ Name = "Sirius";           Path = "$env:APPDATA\Sirius"                 },
    @{ Name = "OxSuite";          Path = "$env:LOCALAPPDATA\OxSuite"           },
    @{ Name = "Zenith";           Path = "$env:APPDATA\Zenith"                 },
    @{ Name = "ThunderAim";       Path = "$env:APPDATA\thunderaim"             },
    @{ Name = "Vega X";           Path = "$env:APPDATA\Vega"                   },
    @{ Name = "Incognito";        Path = "$env:APPDATA\Incognito"              },
    @{ Name = "Krampus";          Path = "$env:APPDATA\Krampus"                },
    @{ Name = "Ro-Exec";          Path = "$env:APPDATA\ro-exec"                },
    @{ Name = "Valyse";           Path = "$env:APPDATA\Valyse"                 },
    @{ Name = "Macsploit";        Path = "$env:APPDATA\Macsploit"              }
)

$executorFound = $false
foreach ($ep in $executorPaths) {
    if (Test-Path $ep.Path) {
        $log.Add("FAIL: Executor path detected -> $($ep.Name) | $($ep.Path)"); $flags++; $executorFound = $true
        try {
            foreach ($f in (Get-ChildItem $ep.Path -Recurse -ErrorAction SilentlyContinue | Where-Object { !$_.PSIsContainer })) {
                if ($f.Extension -in @(".exe",".dll",".sys")) {
                    $sig = (Get-AuthenticodeSignature $f.FullName -ErrorAction SilentlyContinue).Status
                    if ($sig -ne "Valid") { $log.Add("  UNSIGNED: $($f.Name) [Sig: $sig]") }
                }
            }
        } catch {}
    }
}
if (-not $executorFound) { $log.Add("PASS: No known executor installation paths detected.") }


# ==============================================================================
#   SECTION 3C: ROBLOX BINARY INTEGRITY
# ==============================================================================
$log.Add("`n[SECTION 3C: ROBLOX BINARY INTEGRITY]")

$rbxInstallFound = $false
foreach ($rbxBase in @("$env:LOCALAPPDATA\Roblox\Versions","$env:ProgramFiles\Roblox\Versions","${env:ProgramFiles(x86)}\Roblox\Versions")) {
    if (Test-Path $rbxBase) {
        $rbxInstallFound = $true
        try {
            foreach ($ver in (Get-ChildItem $rbxBase -Directory -ErrorAction SilentlyContinue)) {
                $log.Add("INFO: Roblox version folder: $($ver.Name)")
                $rbxExe = Join-Path $ver.FullName "RobloxPlayerBeta.exe"
                if (Test-Path $rbxExe) {
                    $sig    = Get-AuthenticodeSignature $rbxExe -ErrorAction SilentlyContinue
                    $signer = $sig.SignerCertificate.Subject
                    if ($sig.Status -eq "Valid" -and $signer -imatch "Roblox") {
                        $log.Add("PASS: RobloxPlayerBeta.exe validly signed by Roblox.")
                    } elseif ($sig.Status -eq "Valid") {
                        $log.Add("WARN: RobloxPlayerBeta.exe signed but NOT by Roblox -> $signer"); $flags++
                    } else {
                        $log.Add("FAIL: RobloxPlayerBeta.exe signature invalid [$($sig.Status)] — possible tampering!"); $flags++
                    }
                }
                foreach ($dll in (Get-ChildItem $ver.FullName -Filter "*.dll" -ErrorAction SilentlyContinue)) {
                    try {
                        $dllSig    = Get-AuthenticodeSignature $dll.FullName -ErrorAction SilentlyContinue
                        $dllSigner = $dllSig.SignerCertificate.Subject
                        if ($dllSig.Status -ne "Valid") {
                            $log.Add("FAIL: Unsigned DLL in Roblox dir -> $($dll.Name) [Status: $($dllSig.Status)]"); $flags++
                        } elseif ($dllSigner -notmatch "Roblox|Microsoft|NVIDIA|AMD|Intel") {
                            $log.Add("WARN: Non-standard signer on Roblox DLL -> $($dll.Name) | $dllSigner")
                        }
                    } catch {}
                }
                foreach ($exe in (Get-ChildItem $ver.FullName -Filter "*.exe" -ErrorAction SilentlyContinue)) {
                    foreach ($w in $cheatBlacklist) {
                        if ($exe.Name -ilike "*$w*") { $log.Add("FAIL: Cheat EXE inside Roblox directory -> $($exe.FullName)"); $flags++ }
                    }
                }
                foreach ($sf in @("mods","content\dude","shaders","workspace")) {
                    $sfPath = Join-Path $ver.FullName $sf
                    if (Test-Path $sfPath) {
                        $sfFiles = Get-ChildItem $sfPath -Recurse -ErrorAction SilentlyContinue
                        if ($sfFiles) {
                            $log.Add("WARN: Roblox '$sf' folder contains $($sfFiles.Count) file(s).")
                            foreach ($mf in ($sfFiles | Select-Object -First 5)) { $log.Add("  MOD FILE: $($mf.FullName)") }
                        }
                    }
                }
            }
        } catch { $log.Add("INFO: Error scanning Roblox version folder.") }
    }
}
if (-not $rbxInstallFound) { $log.Add("INFO: Roblox installation not found in standard paths.") }


# ==============================================================================
#   SECTION: ROBLOX FFLAGS / CLIENT SETTINGS AUDIT
# ==============================================================================
$log.Add("`n[SECTION: ROBLOX FFLAGS / CLIENT SETTINGS AUDIT]")

$fflagFlagged = $false
$fflagKeywords = @(
    "dfinttaskschedulertargetfps",
    "taskscheduler",
    "fps",
    "render",
    "lighting",
    "graphics",
    "network",
    "latency",
    "physics",
    "debug",
    "interpolate",
    "unlock",
    "vulkan"
)

$fflagPaths = @(
    "$env:LOCALAPPDATA\Roblox\GlobalBasicSettings_13.xml",
    "$env:LOCALAPPDATA\Roblox\ClientSettings\ClientAppSettings.json",
    "$env:LOCALAPPDATA\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json",
    "$env:LOCALAPPDATA\Velostrap\Modifications\ClientSettings\ClientAppSettings.json",
    "$env:LOCALAPPDATA\Fishstrap\Modifications\ClientSettings\ClientAppSettings.json",
    "$env:LOCALAPPDATA\Voidstrap\Modifications\ClientSettings\ClientAppSettings.json"
)

$versionRoots = @(
    "$env:LOCALAPPDATA\Roblox\Versions",
    "$env:ProgramFiles\Roblox\Versions",
    "${env:ProgramFiles(x86)}\Roblox\Versions"
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($root in $versionRoots) {
    foreach ($candidate in (Get-ChildItem $root -Directory -ErrorAction SilentlyContinue)) {
        $fflagPaths += (Join-Path $candidate.FullName "ClientSettings\ClientAppSettings.json")
    }
}

$fflagPaths = $fflagPaths | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

foreach ($ffPath in $fflagPaths) {
    try {
        $content = Get-Content $ffPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) { continue }

        foreach ($kw in $fflagKeywords) {
            if ($content -imatch [regex]::Escape($kw)) {
                $log.Add("FAIL: Suspicious Roblox FFLAG/client setting keyword [$kw] -> $ffPath")
                $flags++
                $fflagFlagged = $true
                break
            }
        }

        try {
            if ($ffPath -like "*.json") {
                $json = $content | ConvertFrom-Json -ErrorAction Stop
                foreach ($prop in $json.PSObject.Properties) {
                    $pairText = "$($prop.Name)=$($prop.Value)"
                    if (Test-SuspiciousIndicator $pairText -BlacklistOnly) {
                        $log.Add("FAIL: Blacklisted term present in Roblox client settings -> $pairText | $ffPath")
                        $flags++
                        $fflagFlagged = $true
                    }
                }
            }
        } catch {}
    } catch {
        $log.Add("INFO: Could not read Roblox client settings file -> $ffPath")
    }
}

if (-not $fflagFlagged) { $log.Add("PASS: No suspicious Roblox FFLAG/client setting overrides detected.") }


# ==============================================================================
#   SECTION 4: DEFENDER SECURITY AUDIT
# ==============================================================================
$log.Add("`n[SECTION 4: DEFENDER SECURITY AUDIT]")

try {
    $mp   = Get-MpComputerStatus
    $pref = Get-MpPreference
    if ($mp.RealTimeProtectionEnabled)      { $log.Add("PASS: Real-time protection enabled.")  } else { $log.Add("FAIL: Real-time protection disabled.");  $flags++ }
    if ($mp.BehaviorMonitorEnabled)         { $log.Add("PASS: Behaviour monitoring enabled.")  } else { $log.Add("FAIL: Behaviour monitoring disabled.");  $flags++ }
    if ($mp.IOAVProtectionEnabled)          { $log.Add("PASS: IOAV protection enabled.")       } else { $log.Add("FAIL: IOAV protection disabled.");       $flags++ }
    if (-not $pref.DisableBlockAtFirstSeen) { $log.Add("PASS: Cloud protection enabled.")      } else { $log.Add("FAIL: Cloud protection disabled.");      $flags++ }
} catch { $log.Add("FAIL: Could not read Defender status."); $flags++ }

try {
    if ($pref.ExclusionPath -or $pref.ExclusionProcess -or $pref.ExclusionExtension) {
        $log.Add("FAIL: Defender exclusions detected."); $flags++
        foreach ($e in $pref.ExclusionPath)      { $log.Add("  EXCLUSION PATH:    $e") }
        foreach ($e in $pref.ExclusionProcess)   { $log.Add("  EXCLUSION PROCESS: $e") }
        foreach ($e in $pref.ExclusionExtension) { $log.Add("  EXCLUSION EXT:     $e") }
    } else { $log.Add("PASS: No Defender exclusions configured.") }
} catch {}

try {
    if ($pref.ThreatIDDefaultAction_Ids) { $log.Add("FAIL: Allowed threat overrides detected."); $flags++ }
    else                                 { $log.Add("PASS: No allowed threat overrides.") }
} catch {}

Scan-RegistryTree "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction" "Threat ID Actions"
Scan-RegistryTree "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"         "Defender Exclusion Extensions"

try {
    $notifIssues = $false
    $notifKey    = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"
    if (Test-Path $notifKey) {
        foreach ($sk in (Get-ChildItem $notifKey -ErrorAction SilentlyContinue)) {
            try {
                foreach ($p in (Get-ItemProperty $sk.PSPath -ErrorAction SilentlyContinue).PSObject.Properties) {
                    if ($p.MemberType -eq "NoteProperty" -and $p.Value -eq 0) {
                        $log.Add("FAIL: Notification disabled -> $($sk.PSChildName) | $($p.Name)"); $flags++; $notifIssues = $true
                    }
                }
            } catch {}
        }
        if (-not $notifIssues) { $log.Add("PASS: Notifications appear enabled.") }
    }
} catch {}


# ==============================================================================
#   SECTION: DEFENDER PROTECTION HISTORY
# ==============================================================================
Update-ScanProgress -Percent 32 
$log.Add("`n[SECTION: DEFENDER PROTECTION HISTORY]")

try {
    $threats    = Get-MpThreat -ErrorAction SilentlyContinue
    $detections = Get-MpThreatDetection -ErrorAction SilentlyContinue
    if ($detections) {
        foreach ($d in $detections) {
            $match    = $threats | Where-Object { $_.ThreatID -eq $d.ThreatID } | Select-Object -First 1
            $name     = if ($match.ThreatName) { $match.ThreatName } else { "Unknown" }
            $severity = switch ($match.SeverityID) { 1{"Low"} 2{"Moderate"} 4{"High"} 5{"Severe"} default{"Unknown"} }
            $category = switch ($match.CategoryID) {
                1{"Adware"} 2{"Spyware"} 3{"PasswordStealer"} 4{"TrojanDownloader"} 5{"Worm"} 6{"Backdoor"}
                7{"RAT"} 8{"Trojan"} 23{"Exploit"} 27{"Virus"} 30{"HackTool"} 32{"Ransomware"} 33{"MaliciousURL"}
                default{"Other"}
            }
            $process = if ($d.ProcessName) { $d.ProcessName } else { "N/A" }
            $log.Add("THREAT | Name: $name | Severity: $severity | Category: $category | Process: $process | Detected: $($d.InitialDetectionTime)")
        }
    } else { $log.Add("PASS: No threat detections in protection history.") }
} catch { $log.Add("INFO: Could not retrieve Defender protection history.") }


# ==============================================================================
#   SECTION 5: REGISTRY FORENSICS
# ==============================================================================
$log.Add("`n[SECTION 5: REGISTRY FORENSICS]")

$regPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\Microsoft\Tracing",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    "HKCU:\Software\Classes\ms-settings",
    "HKCU:\Software\Classes\mscfile\shell\open\command",
    "HKCU:\Software\Classes\exefile\shell\runas\command",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"
)

foreach ($p in $regPaths) {
    if (Test-Path $p) {
        try {
            $item  = Get-Item -Path $p -ErrorAction SilentlyContinue
            $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            foreach ($name in $item.GetValueNames()) {
                foreach ($w in $cheatBlacklist) {
                    if ($name -ilike "*$w*") { $log.Add("FAIL: Registry name match [$w] in $p -> $name"); $flags++ }
                }
            }
            $props.PSObject.Properties | ForEach-Object {
                $val = $_.Value.ToString()
                foreach ($w in $cheatBlacklist) {
                    if ($val -ilike "*$w*") { $log.Add("FAIL: Registry value match [$w] in $p -> $val"); $flags++ }
                }
            }
        } catch {}
    }
}


# ==============================================================================
#   SECTION: SHELLBAGS ANALYSIS
# ==============================================================================
Update-ScanProgress -Percent 35  
$log.Add("`n[SECTION: SHELLBAGS ANALYSIS]")

$shellbagFlagged = $false
foreach ($root in @(
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
    "HKCU:\Software\Microsoft\Windows\Shell\Bags"
)) {
    if (Test-Path $root) {
        try {
            foreach ($key in (Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue)) {
                try {
                    (Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue).PSObject.Properties |
                    Where-Object { $_.MemberType -eq "NoteProperty" -and $_.Name -notlike "PS*" } |
                    ForEach-Object {
                        $val = $_.Value.ToString()
                        foreach ($w in $cheatBlacklist) {
                            if ($val -ilike "*$w*") {
                                $log.Add("FAIL: Shellbag match [$w] -> $val"); $flags++; $shellbagFlagged = $true
                            }
                        }
                    }
                } catch {}
            }
        } catch {}
    }
}
if (-not $shellbagFlagged) { $log.Add("PASS: No suspicious entries in shellbags.") }


# ==============================================================================
#   SECTION 6: ACTIVE PROCESS AUDIT
# ==============================================================================
$log.Add("`n[SECTION 6: ACTIVE PROCESS AUDIT]")

$macroDetect  = @("autohotkey","ahk","macro","logitech","itask","x-mouse","tinytask","autoclicker","jitbit","xdotool","macrorecorder")
$recordDetect = @("obs64","obs32","streamlabs","medal","shadowplay","nvcontainer","bandicam","fraps","playnite","xsplit")

foreach ($proc in (Get-ProcessSnapshotWithUser)) {
    $desc = ""; try { $desc = $proc.MainModule.FileVersionInfo.FileDescription } catch {}
    foreach ($c in $cheatBlacklist) {
        if ($proc.ProcessName -ilike "*$c*" -or $desc -ilike "*$c*") {
            $log.Add("FAIL: Active cheat process -> $($proc.ProcessName) ($desc)"); $flags++
        }
    }
    foreach ($m in $macroDetect) {
        if ($proc.ProcessName -ilike "*$m*" -or $desc -ilike "*$m*") {
            $log.Add("INFO: Macro/automation process -> $($proc.ProcessName)")
        }
    }
    foreach ($r in $recordDetect) {
        if ($proc.ProcessName -ilike "*$r*") {
            $rec = "IDLE"
            try { if (($proc.Modules.ModuleName -match "nvenc|nvapi|obs|vce") -and ($proc.CPU -gt 0.01)) { $rec = "ACTIVE" } } catch {}
            $log.Add("INFO: Recording process -> $($proc.ProcessName) [$rec]")
        }
    }
}


# ==============================================================================
#   SECTION: DLL INJECTION HEURISTICS
# ==============================================================================
Update-ScanProgress -Percent 38  
$log.Add("`n[SECTION: DLL INJECTION HEURISTICS]")

$dllFindings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$strongSuspiciousDllRegex = [regex]::new('(cheatengine|dbk64|dbk32|synapse|scriptware|jjsploit|wearedevs|fluxus|sirhurt|processhacker|pe-sieve|moneta|manualmap|manual_map|reflective|reflectiveloader|injector|dllinject|hook|executor|exploit|aimbot|triggerbot|wallhack|esp|autohotkey|keyauth|dx9ware|darkdex|infiniteyield|remotespy)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$unsignedStatus = @('NotSigned','HashMismatch','NotTrusted','UnknownError')

foreach ($proc in (Get-ProcessSnapshot)) {
    try {
        foreach ($m in $proc.Modules) {
            $modulePath = $m.FileName
            $pathLow    = $modulePath.ToLower()
            $fileName   = [System.IO.Path]::GetFileName($modulePath).ToLower()

            if ($dllFindings.Contains("$($proc.ProcessName)|$modulePath")) { continue }

            $isDriveRoot  = $modulePath -match '^[A-Za-z]:\\[^\\]+\.dll$'
            $isUserSpace  = $pathLow -match '\\users\\[^\\]+\\(appdata|downloads|desktop|documents)|\\appdata\\|\\temp\\|\\roaming\\'
            $isSystemLike = ($normalDllRoots | Where-Object { $_ -and $pathLow.StartsWith($_) }).Count -gt 0
            $nameStrong   = $strongSuspiciousDllRegex.IsMatch($fileName) -or $strongSuspiciousDllRegex.IsMatch($pathLow)
            $pathWeak     = (Test-SuspiciousIndicator $fileName) -or (Test-SuspiciousIndicator $pathLow)

            if ($isDriveRoot -and ($nameStrong -or $pathWeak)) {
                if ($dllFindings.Add("$($proc.ProcessName)|$modulePath")) {
                    $log.Add("FAIL: Suspicious DLL at drive root in [$($proc.ProcessName)] -> $modulePath")
                    $flags++
                }
                continue
            }

            if ($isUserSpace) {
                if (Test-KnownBenignDllPath $pathLow) { continue }

                $sigState = $null
                try { $sigState = (Get-AuthenticodeSignature $modulePath -ErrorAction SilentlyContinue).Status.ToString() } catch {}

                if ($nameStrong -or (($unsignedStatus -contains $sigState) -and $pathWeak)) {
                    if ($dllFindings.Add("$($proc.ProcessName)|$modulePath")) {
                        $log.Add("FAIL: Suspicious user-space DLL in [$($proc.ProcessName)] -> $modulePath" + $(if($sigState){" [Sig: $sigState]"}else{""}))
                        $flags++
                    }
                }
                continue
            }

            if ((-not $isSystemLike) -and $nameStrong) {
                $sigState = $null
                try { $sigState = (Get-AuthenticodeSignature $modulePath -ErrorAction SilentlyContinue).Status.ToString() } catch {}
                if (($null -eq $sigState) -or ($unsignedStatus -contains $sigState) -or $pathWeak) {
                    if ($dllFindings.Add("$($proc.ProcessName)|$modulePath")) {
                        $log.Add("FAIL: Suspicious injected DLL in [$($proc.ProcessName)] -> $modulePath" + $(if($sigState){" [Sig: $sigState]"}else{""}))
                        $flags++
                    }
                }
            }
        }
    } catch {}
}

# Roblox-specific DLL audit
$robloxProc = Get-Process -Name "RobloxPlayerBeta" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($robloxProc) {
    try {
        $rbxDir = [System.IO.Path]::GetDirectoryName($robloxProc.MainModule.FileName).ToLower()
        foreach ($m in $robloxProc.Modules) {
            $mPath    = $m.FileName.ToLower()
            $fileName = [System.IO.Path]::GetFileName($m.FileName).ToLower()
            $isKnownRoot = ($normalDllRoots | Where-Object { $_ -and $mPath.StartsWith($_) }).Count -gt 0
            $isRobloxRoot = $mPath.StartsWith($rbxDir)
            $nameStrong = $strongSuspiciousDllRegex.IsMatch($fileName) -or $strongSuspiciousDllRegex.IsMatch($mPath)

            if ($isRobloxRoot) { continue }

            if (-not $isKnownRoot) {
                $sigState = $null
                $signer   = ''
                try {
                    $sigObj = Get-AuthenticodeSignature $m.FileName -ErrorAction SilentlyContinue
                    $sigState = $sigObj.Status.ToString()
                    if ($sigObj.SignerCertificate) { $signer = $sigObj.SignerCertificate.Subject }
                } catch {}

                $badSigner = $signer -and ($signer -notmatch 'Microsoft|Roblox|NVIDIA|AMD|Intel')
                if ($nameStrong -or ($unsignedStatus -contains $sigState) -or $badSigner) {
                    $log.Add("FAIL: Suspicious non-system DLL in Roblox -> $($m.FileName)" + $(if($sigState){" [Sig: $sigState]"}else{""}) + $(if($signer){" [Signer: $signer]"}else{""}))
                    $flags++
                }
            }
        }
    } catch { $log.Add("INFO: Could not enumerate Roblox modules (may be protected).") }
} else {
    $log.Add("INFO: Roblox not currently running — module check skipped.")
}


# ==============================================================================
#   SECTION: ROBLOX MEMORY INTEGRITY
# ==============================================================================
Update-ScanProgress -Percent 41 
$log.Add("`n[SECTION: ROBLOX MEMORY INTEGRITY]")

$rbxProc = Get-Process -Name "RobloxPlayerBeta" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($rbxProc) {
    try {
        # Working set check — legitimate Roblox typically runs 300MB–1.5GB
        $wsMB = [math]::Round($rbxProc.WorkingSet64 / 1MB, 2)
        $log.Add("INFO: Roblox WorkingSet: $wsMB MB")
        if ($wsMB -gt 2048) {
            $log.Add("WARN: Roblox memory usage is unusually high ($wsMB MB) — possible memory injection."); $flags++
        } elseif ($wsMB -lt 50) {
            $log.Add("WARN: Roblox memory usage is unusually low ($wsMB MB) — process may be spoofed.")
        } else {
            $log.Add("PASS: Roblox memory usage is within normal range.")
        }

        # Private bytes check — consistently high private bytes suggest foreign allocations
        $privateMB = [math]::Round($rbxProc.PrivateMemorySize64 / 1MB, 2)
        $log.Add("INFO: Roblox Private Bytes: $privateMB MB")
        if ($privateMB -gt 1500) {
            $log.Add("WARN: Roblox private memory is elevated ($privateMB MB) — potential injected allocations."); $flags++
        }

        # Handle count — cheats that hook or read memory inflate handle counts
        $log.Add("INFO: Roblox Handle Count: $($rbxProc.HandleCount)")
        if ($rbxProc.HandleCount -gt 3000) {
            $log.Add("WARN: Roblox handle count elevated ($($rbxProc.HandleCount)) — possible hooked process."); $flags++
        }

        # Thread count — injected DLLs typically add threads
        $log.Add("INFO: Roblox Thread Count: $($rbxProc.Threads.Count)")
        if ($rbxProc.Threads.Count -gt 200) {
            $log.Add("WARN: Roblox thread count elevated ($($rbxProc.Threads.Count)) — possible injection."); $flags++
        }

        # Debugger check via kernel32 IsDebuggerPresent alternative
        try {
            $rbxFull = [System.Diagnostics.Process]::GetProcessById($rbxProc.Id)
            if ($rbxFull.EnableRaisingEvents -eq $true) {
                $log.Add("INFO: Roblox has EnableRaisingEvents set — monitored externally.")
            }
        } catch {}

        # Check for external processes with handles into Roblox
        $log.Add("--- Processes Holding Handles to Roblox ---")
        $rbxHandleFound = $false
        try {
            $handleOutput = & "$env:SystemRoot\System32\handle.exe" -p $rbxProc.Id 2>$null
            if ($handleOutput) {
                foreach ($line in $handleOutput) {
                    if ($line -match "\\RobloxPlayerBeta") {
                        $log.Add("INFO: External handle to Roblox -> $line")
                    }
                }
            }
        } catch {}

        # Cross-check — any process that has read handle count anomalies
        foreach ($proc in (Get-ProcessSnapshot)) {
            if ($proc.Id -eq $rbxProc.Id) { continue }
            foreach ($w in $cheatBlacklist) {
                if ($proc.ProcessName -ilike "*$w*") {
                    $log.Add("FAIL: Cheat process co-running with Roblox -> $($proc.ProcessName) (PID $($proc.Id))"); $flags++
                }
            }
        }

        $log.Add("PASS: Roblox memory integrity check complete.")
    } catch {
        $log.Add("INFO: Could not fully audit Roblox memory. Error: $($_.Exception.Message)")
    }
} else {
    $log.Add("INFO: Roblox is not running — memory integrity check skipped.")
}


# ==============================================================================
#   SECTION: CHEAT ENGINE DEEP SCAN
# ==============================================================================
Update-ScanProgress -Percent 44  
$log.Add("`n[SECTION: CHEAT ENGINE DEEP SCAN]")
$ceFound = $false

foreach ($proc in (Get-ProcessSnapshot)) {
    foreach ($cp in @("cheatengine","cheatengine-x86_64","cheatengine-i386","dbk64","dbk32","artmoney","tsearch","scanmem")) {
        if ($proc.ProcessName -ilike "*$cp*") {
            $log.Add("FAIL: Cheat Engine / memory tool running -> $($proc.ProcessName)"); $flags++; $ceFound = $true
        }
    }
}

foreach ($dp in @("$env:SystemRoot\System32\drivers\dbk64.sys","$env:SystemRoot\System32\drivers\dbk32.sys","$env:SystemRoot\SysWOW64\drivers\dbk64.sys","$env:SystemRoot\SysWOW64\drivers\dbk32.sys")) {
    if (Test-Path $dp) { $log.Add("FAIL: Cheat Engine kernel driver present -> $dp"); $flags++; $ceFound = $true }
}

try {
    foreach ($svc in (Get-ServiceSnapshot)) {
        if ($svc.Name -ilike "*dbk*" -or $svc.Name -ilike "*cheatengine*") {
            $log.Add("FAIL: Cheat Engine service -> $($svc.Name) [$($svc.Status)]"); $flags++; $ceFound = $true
        }
    }
} catch {}

foreach ($rp in @("HKLM:\SOFTWARE\Cheat Engine","HKLM:\SOFTWARE\WOW6432Node\Cheat Engine","HKCU:\Software\Cheat Engine")) {
    if (Test-Path $rp) { $log.Add("FAIL: Cheat Engine registry key -> $rp"); $flags++; $ceFound = $true }
}

try {
    $ceInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -ilike "*Cheat Engine*" -or $_.DisplayName -ilike "*ArtMoney*" }
    if ($ceInstalled) {
        foreach ($ci in $ceInstalled) { $log.Add("FAIL: Memory editor installed -> $($ci.DisplayName) at $($ci.InstallLocation)"); $flags++; $ceFound = $true }
    }
} catch {}

try {
    foreach ($pf in (Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue)) {
        $name = ($pf.BaseName -split "-")[0]
        if ($name -ilike "*cheatengine*" -or $name -ilike "*dbk64*" -or $name -ilike "*dbk32*") {
            $log.Add("FAIL: CE prefetch entry -> $($pf.BaseName) | Last: $($pf.LastWriteTime)"); $flags++; $ceFound = $true
        }
    }
} catch {}

foreach ($proc in (Get-ProcessSnapshot | Where-Object { $_.MainWindowTitle })) {
    if ($proc.MainWindowTitle -imatch "Cheat Engine|Memory Scanner|ArtMoney") {
        $log.Add("FAIL: Memory editor window open -> '$($proc.MainWindowTitle)'"); $flags++; $ceFound = $true
    }
}
if (-not $ceFound) { $log.Add("PASS: No Cheat Engine or memory editor indicators detected.") }


# ==============================================================================
#   SECTION: USB DRIVE LOG
# ==============================================================================
Update-ScanProgress -Percent 47 
$log.Add("`n[SECTION: USB DRIVE LOG]")

try {
    $usbStorKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    if (Test-Path $usbStorKey) {
        foreach ($type in (Get-ChildItem $usbStorKey -ErrorAction SilentlyContinue)) {
            foreach ($inst in (Get-ChildItem $type.PSPath -ErrorAction SilentlyContinue)) {
                try {
                    $props        = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
                    $friendlyName = if ($props.FriendlyName) { $props.FriendlyName } else { $type.PSChildName }
                    $serialNum    = $inst.PSChildName -replace "&\d$", ""
                    $lastConn     = "Unknown"
                    $logSubKey    = Join-Path $inst.PSPath "Properties\{83da6326-97a6-4088-9453-a1923f573b29}"
                    if (Test-Path $logSubKey) {
                        $timeProp = Get-ChildItem $logSubKey -ErrorAction SilentlyContinue |
                                    Where-Object { $_.PSChildName -match "0064|0066" } | Select-Object -First 1
                        if ($timeProp) {
                            $raw = (Get-ItemProperty $timeProp.PSPath -ErrorAction SilentlyContinue).'(default)'
                            if ($raw) { $lastConn = $raw }
                        }
                    }
                    $log.Add("USB HISTORY | Device: $friendlyName | Serial: $serialNum | Last Seen: $lastConn")
                    foreach ($w in $cheatBlacklist) {
                        if ($friendlyName -ilike "*$w*") { $log.Add("FAIL: Suspicious USB device name [$w] -> $friendlyName"); $flags++ }
                    }
                } catch {}
            }
        }
    } else { $log.Add("INFO: No USBSTOR registry key found.") }
} catch {}

try {
    $usbDisks = Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq "USB" }
    if ($usbDisks) {
        foreach ($disk in $usbDisks) {
            $log.Add("USB ACTIVE | Model: $($disk.Model) | Serial: $($disk.SerialNumber) | Size: $([math]::Round($disk.Size / 1GB, 2)) GB")
            $partitions = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($disk.DeviceID -replace '\\\\','\\')'}  WHERE AssocClass=Win32_DiskDriveToDiskPartition" -ErrorAction SilentlyContinue
            foreach ($part in $partitions) {
                $logicals = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($part.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition" -ErrorAction SilentlyContinue
                foreach ($drive in $logicals) {
                    $log.Add("USB DRIVE: $($drive.DeviceID) ($($drive.VolumeName))")
                    try {
                        foreach ($f in (Get-ChildItem "$($drive.DeviceID)\" -Depth 2 -ErrorAction SilentlyContinue)) {
                            foreach ($w in $cheatBlacklist) {
                                if ($f.Name -ilike "*$w*") { $log.Add("FAIL: Suspicious file on USB [$w] -> $($f.FullName)"); $flags++ }
                            }
                        }
                    } catch {}
                }
            }
        }
    } else { $log.Add("PASS: No USB drives currently connected.") }
} catch {}


# ==============================================================================
#   SECTION: DMA DETECTION
# ==============================================================================
Update-ScanProgress -Percent 50 
$log.Add("`n[SECTION: DMA DETECTION]")

$dmaProcessList = @("pcileech","dmacheck","fpga","squirrel","lambdaconcept","screamer","enigma","komodo","75t","35t","ac701","sp605","pcimem","rweverything","rw-everything","MemProcFS","vmm","dma_read","dma_write","dma_tool")
$dmaDriverList  = @("pcileech","winpmem","dumpit","comae","pmem","fpga","xdma","ftd3xx","ftd2xx","netchip","screamer","lambdaconcept","squirrel")
$dmaHwList      = @("Xilinx","Altera","Lattice","FPGA","PCILeech","Screamer","LambdaConcept","Squirrel","Enigma","USB3380","EXP19301","AX99100")

$dmaFound = $false
foreach ($proc in (Get-ProcessSnapshot)) {
    foreach ($d in $dmaProcessList) {
        if ($proc.ProcessName -ilike "*$d*") { $log.Add("FAIL: DMA process -> $($proc.ProcessName)"); $flags++; $dmaFound = $true }
    }
}
if (-not $dmaFound) { $log.Add("PASS: No DMA processes detected.") }

$dmaDriverFound = $false
try {
    foreach ($svc in (Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        foreach ($d in $dmaDriverList) {
            if ($svc.Name -ilike "*$d*" -or $svc.PathName -ilike "*$d*") {
                $log.Add("FAIL: DMA driver -> $($svc.Name) | $($svc.PathName)"); $flags++; $dmaDriverFound = $true
            }
        }
    }
    if (-not $dmaDriverFound) { $log.Add("PASS: No DMA drivers detected.") }
} catch {}

$dmaHwFound = $false
try {
    foreach ($dev in (Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue)) {
        foreach ($d in $dmaHwList) {
            if ($dev.Name -ilike "*$d*" -or $dev.Description -ilike "*$d*" -or $dev.Manufacturer -ilike "*$d*") {
                $log.Add("FAIL: Suspicious DMA hardware -> $($dev.Name) | Mfg: $($dev.Manufacturer)"); $flags++; $dmaHwFound = $true
            }
        }
    }
    if (-not $dmaHwFound) { $log.Add("PASS: No DMA hardware detected.") }
} catch {}

$dmaRegFound = $false
foreach ($rp in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU","HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
    if (Test-Path $rp) {
        try {
            (Get-ItemProperty $rp -ErrorAction SilentlyContinue).PSObject.Properties | ForEach-Object {
                $val = $_.Value.ToString()
                foreach ($d in $dmaProcessList) {
                    if ($val -ilike "*$d*") { $log.Add("FAIL: DMA artefact in registry [$d] -> $val"); $flags++; $dmaRegFound = $true }
                }
            }
        } catch {}
    }
}
if (-not $dmaRegFound) { $log.Add("PASS: No DMA registry artefacts found.") }

$dmaPfFound = $false
try {
    foreach ($pf in (Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue)) {
        $exeName = ($pf.BaseName -split "-")[0]
        foreach ($d in $dmaProcessList) {
            if ($exeName -ilike "*$d*") { $log.Add("FAIL: DMA tool in prefetch -> $exeName | Last Run: $($pf.LastWriteTime)"); $flags++; $dmaPfFound = $true }
        }
    }
    if (-not $dmaPfFound) { $log.Add("PASS: No DMA tools in prefetch.") }
} catch {}


# ==============================================================================
#   SECTION: NETWORK FORENSICS
# ==============================================================================
Update-ScanProgress -Percent 53  
$log.Add("`n[SECTION: NETWORK FORENSICS]")

try {
    $hostsLines = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction Stop |
                  Where-Object { $_ -notmatch "^\s*#" -and $_ -notmatch "^\s*$" }
    $hostsClean = $true
    foreach ($line in $hostsLines) {
        if ($line -imatch "127\.0\.0\.1\s+localhost|::1\s+localhost") { continue }
        $log.Add("INFO: Non-default hosts entry -> $line")
        foreach ($sh in @("roblox","bloxstrap","discord","microsoft","windows","update","defender","windowsupdate")) {
            if ($line -ilike "*$sh*") { $log.Add("FAIL: Hosts file redirecting [$sh] -> $line"); $flags++; $hostsClean = $false }
        }
    }
    if ($hostsClean) { $log.Add("PASS: Hosts file is clean.") }
} catch {}

try {
    $suspPorts   = @(1337, 4444, 31337, 9999, 6666, 7777, 1234, 54321, 6969, 8008)
    $portFlagged = $false
    foreach ($conn in (Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" })) {
        if ($conn.RemotePort -in $suspPorts) {
            $pName = try { (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { "Unknown" }
            $log.Add("WARN: Connection on suspicious port -> $($conn.RemoteAddress):$($conn.RemotePort) | $pName (PID $($conn.OwningProcess))"); $portFlagged = $true
        }
    }
    if (-not $portFlagged) { $log.Add("PASS: No connections on suspicious ports.") }
} catch {}

try {
    $dnsHit = $false
    foreach ($entry in (Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        foreach ($cd in @("keyauth.win","keyauth.xyz","wearedevs.net","synapse.to","krnl.ca","scriptware.net","trigon.to","solara.to","wave.gg","celery.rip","fluxteam.net","exploit.in","nulled.to","v3rmillion.net")) {
            if ($entry.Entry -ilike "*$cd*") {
                $log.Add("FAIL: Cheat DNS cache entry -> $($entry.Entry) -> $($entry.Data)"); $flags++; $dnsHit = $true
            }
        }
    }
    if (-not $dnsHit) { $log.Add("PASS: No cheat-related DNS cache entries.") }
} catch {}


# ==============================================================================
#   SECTION: WINDOWS EVENT LOG FORENSICS
# ==============================================================================
Update-ScanProgress -Percent 56 
$log.Add("`n[SECTION: WINDOWS EVENT LOG FORENSICS]")

# Process creation (Event 4688) — flag only cheat blacklist hits
try {
    $evtHits = 0
    Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=4688; StartTime=(Get-Date).AddDays(-7) } -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object {
        $msg = $_.Message
        foreach ($w in $cheatBlacklist) {
            if ($msg -ilike "*$w*") {
                $exe = if ($msg -match "New Process Name:\s+(.+)") { $matches[1].Trim() } else { "Unknown" }
                $log.Add("FAIL: Event 4688 — cheat process launch [$w] at $($_.TimeCreated) | $exe"); $flags++; $evtHits++; break
            }
        }
    }
    if ($evtHits -eq 0) { $log.Add("PASS: No suspicious process launches in Security log (last 7 days).") }
} catch { $log.Add("INFO: Security event log unavailable (process auditing may be off).") }

# PowerShell Script Block (Event 4104) — flag only suspicious patterns
try {
    $psHits      = 0
    $psPatterns  = @("Set-MpPreference","DisableRealtimeMonitoring","DisableBehaviorMonitoring","bypass.*amsi","VirtualAlloc","shellcode","DownloadString\(","DownloadFile\(")
    Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104; StartTime=(Get-Date).AddDays(-3) } -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($pat in $psPatterns) {
            if ($_.Message -imatch $pat) {
                $snippet = ($_.Message -replace "`r|`n"," ").Substring(0,[Math]::Min(150,$_.Message.Length))
                $log.Add("FAIL: PowerShell suspicious block [$pat] at $($_.TimeCreated): $snippet"); $flags++; $psHits++; break
            }
        }
    }
    if ($psHits -eq 0) { $log.Add("PASS: No suspicious PowerShell blocks (last 3 days).") }
} catch { $log.Add("INFO: PowerShell event log unavailable.") }

# App crash log (Event 1000) — flag only cheat matches
try {
    $crashHits = 0
    Get-WinEvent -FilterHashtable @{ LogName="Application"; Id=1000; StartTime=(Get-Date).AddDays(-14) } -MaxEvents 300 -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($w in $cheatBlacklist) {
            if ($_.Message -ilike "*$w*") {
                $log.Add("WARN: Crash record match [$w] at $($_.TimeCreated)"); $flags++; $crashHits++; break
            }
        }
    }
    if ($crashHits -eq 0) { $log.Add("PASS: No cheat-related crash records (last 14 days).") }
} catch { $log.Add("INFO: Application event log unavailable.") }


# ==============================================================================
#   SECTION: SCHEDULED TASKS FORENSICS
# ==============================================================================
Update-ScanProgress -Percent 59 
$log.Add("`n[SECTION: SCHEDULED TASKS FORENSICS]")

try {
    $taskFlagged = $false
    foreach ($task in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $taskName  = $task.TaskName
        $actionStr = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() } | Where-Object { $_ -notmatch "^\s*$" }) -join " | "
        foreach ($w in $cheatBlacklist) {
            if ($taskName -ilike "*$w*" -or $actionStr -ilike "*$w*") {
                $log.Add("FAIL: Suspicious scheduled task [$w] -> $($task.TaskPath)$taskName | $actionStr"); $flags++; $taskFlagged = $true; break
            }
        }
        if ($actionStr -imatch "appdata|\\temp\\|roaming" -and $task.State -ne "Disabled") {
            $log.Add("WARN: Task running from user-writable path -> $($task.TaskPath)$taskName | $actionStr")
        }
    }
    if (-not $taskFlagged) { $log.Add("PASS: No suspicious scheduled tasks detected.") }
} catch {}


# ==============================================================================
#   SECTION: NAMED PIPE & MUTEX DETECTION
# ==============================================================================
Update-ScanProgress -Percent 62 
$log.Add("`n[SECTION: NAMED PIPE & MUTEX DETECTION]")

$pipeKw = @("SynapseX","Synapse","KRNL","Solara","Celery","Wave","Evon","Delta","JJSploit","Fluxus","ScriptWare","Elysian","Trigon","ArceusX","Hydrogen","NightHub","HohoHub","ThunderAim","WeAreDevs","Aimmy","Xeno","Horizon","DX9Ware","Matcha","executor","InjectorPipe","RobloxCheat","rbxcheat")
try {
    $pipeHit = $false
    foreach ($pipe in (Get-ChildItem "\\.\pipe\" -ErrorAction SilentlyContinue)) {
        foreach ($kw in $pipeKw) {
            if ($pipe.Name -ilike "*$kw*") {
                $log.Add("FAIL: Suspicious named pipe -> $($pipe.Name)"); $flags++; $pipeHit = $true
            }
        }
    }
    if (-not $pipeHit) { $log.Add("PASS: No suspicious named pipes detected.") }
} catch { $log.Add("INFO: Named pipe scan requires elevated access.") }


# ==============================================================================
#   SECTION: TEMP FOLDER FORENSICS
# ==============================================================================
Update-ScanProgress -Percent 65 
$log.Add("`n[SECTION: TEMP FOLDER FORENSICS]")

$recentCutoff = (Get-Date).AddDays(-3)
foreach ($tf in (@($env:TEMP, $env:TMP, "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\Temp") | Select-Object -Unique)) {
    if (Test-Path $tf) {
        try {
            Get-ChildItem $tf -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $recentCutoff -and $_.Extension -in @(".exe",".dll",".sys",".bat",".ps1",".vbs",".zip",".rar",".7z") } |
            ForEach-Object {
                $hitBl = $false
                foreach ($w in $cheatBlacklist) {
                    if ($_.Name -ilike "*$w*") { $log.Add("FAIL: Cheat file in temp [$w] -> $($_.FullName)"); $flags++; $hitBl = $true; break }
                }
                if (-not $hitBl -and $_.Extension -in @(".exe",".dll",".sys")) {
                    $sig = (Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue).Status
                    if ($sig -ne "Valid") { $log.Add("WARN: Unsigned binary in temp (recent) -> $($_.FullName) [Sig: $sig]") }
                }
            }
        } catch {}
    }
}
$log.Add("INFO: Temp folder forensics complete.")



# ==============================================================================
#   BAM ENTRIES (collect now, show PAH near end)
# ==============================================================================
Update-ScanProgress -Percent 68 
$log.Add("`n[SECTION: BAM EXECUTION HISTORY]")

$script:BamPahData = @()
try {
    $bamRootPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    ) | Where-Object { Test-Path $_ }

    $bamEntries = New-Object System.Collections.Generic.List[object]
    $bamSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($root in $bamRootPaths) {
        foreach ($userKey in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            $sid = $userKey.PSChildName
            $user = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }

            try {
                $item = Get-Item -LiteralPath $userKey.PSPath -ErrorAction Stop
                foreach ($valueName in $item.GetValueNames()) {
                    if ([string]::IsNullOrWhiteSpace($valueName)) { continue }

                    $raw = $item.GetValue($valueName, $null, 'DoNotExpandEnvironmentNames')
                    if ($raw -isnot [byte[]]) { continue }

                    $safeTime = Get-SafeBamTime -Data $raw
                    if ($null -eq $safeTime) { continue }

                    $exeFile   = Split-Path -Leaf $valueName
                    $fullPath  = Convert-DevicePathToDrivePath $valueName
                    $timeLocal = $safeTime.ToLocalTime()
                    $rowKey    = "{0}|{1}|{2}" -f $user, $fullPath, $timeLocal.ToString('o')
                    if (-not $bamSeen.Add($rowKey)) { continue }

                    if (Test-BlacklistTerm "$exeFile $fullPath") {
                        $script:log.Add("FAIL: BAM entry blacklist match -> $exeFile | Path: $fullPath | Last Run: $($timeLocal.ToString('yyyy-MM-dd HH:mm:ss')) | User: $user")
                        $script:flags++
                    }

                    $log.Add("BAM: $exeFile | Last Run: $($timeLocal.ToString('yyyy-MM-dd HH:mm:ss')) | User: $user | Path: $fullPath")

                    $sig = ""
                    if ($fullPath -and (Test-Path $fullPath)) {
                        try { $sig = (Get-AuthenticodeSignature $fullPath -ErrorAction SilentlyContinue).Status } catch {}
                    }

                    $bamEntries.Add([PSCustomObject]@{
                        SortTime            = $timeLocal
                        "Last Run (Local)" = $timeLocal.ToString('yyyy-MM-dd HH:mm:ss')
                        "Executable"        = $exeFile
                        "Full Path"         = $fullPath
                        "Signature"         = $sig
                        "User"              = $user
                    }) | Out-Null
                }
            } catch {}
        }
    }

    if ($bamEntries.Count -gt 0) {
        $script:BamPahData = @($bamEntries | Sort-Object SortTime -Descending | Select-Object "Last Run (Local)","Executable","Full Path","Signature","User")
    } else {
        $log.Add("INFO: No valid BAM execution entries found.")
    }
} catch {
    $log.Add("INFO: BAM scan error — $($_.Exception.Message)")
}

# ==============================================================================
#   REAL-TIME PROCESS MONITORING (single snapshot)
# ==============================================================================
Update-ScanProgress -Percent 71 
$log.Add("`n[SECTION: REAL-TIME PROCESS SNAPSHOT]")

$snapshotProcs = Get-ProcessSnapshot
$rtHit = $false
foreach ($proc in $snapshotProcs) {
    $name = $proc.ProcessName.ToLower()
    foreach ($w in $cheatBlacklist) {
        if ($name -like "*$w*") { $log.Add("DETECTED: Process snapshot match -> $name"); $flags++; $rtHit = $true; break }
    }
    try { if ($proc.HandleCount -gt 1000) { $log.Add("INFO: High handle count -> $name ($($proc.HandleCount))") } } catch {}
    try { if ($proc.WorkingSet  -gt 500MB) { $log.Add("INFO: High memory usage -> $name ($([math]::Round($proc.WorkingSet/1MB,0)) MB)") } } catch {}
}
if (-not $rtHit) { $log.Add("PASS: No cheat processes in snapshot.") }
$log.Add("INFO: Snapshot captured $($snapshotProcs.Count) processes.")


# ==============================================================================
#   PROCESS EXPLORER AUDIT
# ==============================================================================
Update-ScanProgress -Percent 73  
$log.Add("`n[SECTION: PROCESS EXPLORER AUDIT]")

$peBase    = "C:\ToolsETA"
$peExtract = Join-Path $peBase "ProcessExplorer"
$peZipUrl  = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$peZipPath = Join-Path $peBase "ProcessExplorer.zip"
$peRegUrl  = "https://pastebin.com/raw/gse8NxwU"
$peRegPath = Join-Path $peBase "procexp_config.reg"

foreach ($peName in @("procexp32","procexp64","procexp64a")) {
    Get-ProcessSnapshot | Where-Object { $_.ProcessName.ToLower() -eq $peName } |
        ForEach-Object { try { $_ | Stop-Process -Force -ErrorAction Stop } catch {} }
}

if (Test-Path $peBase) {
    Get-ChildItem -Path $peBase -Force -Recurse | ForEach-Object {
        try {
            if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) { $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::ReadOnly }
            if ($_.Attributes -band [System.IO.FileAttributes]::Hidden)   { $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::Hidden   }
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
        } catch {}
    }
} else {
    try { New-Item -ItemType Directory -Path $peBase -ErrorAction Stop | Out-Null } catch {}
}

try {
    Invoke-WebRequest -Uri $peZipUrl -OutFile $peZipPath -UseBasicParsing -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($peZipPath, $peExtract)
    Remove-Item $peZipPath -Force -ErrorAction SilentlyContinue
} catch { $log.Add("WARNING: Could not download or extract Process Explorer.") }

try {
    Invoke-WebRequest -Uri $peRegUrl -OutFile $peRegPath -UseBasicParsing -ErrorAction Stop
    & "$env:SystemRoot\System32\cmd.exe" /c "reg import `"$peRegPath`"" *> $null
} catch {}

$peExe = Get-ChildItem -Path $peExtract -Filter "procexp64.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($peExe) {
    $peProc = Start-Process -FilePath $peExe.FullName -PassThru
    Start-Sleep -Seconds 1
    $wshell = New-Object -ComObject wscript.shell
    Start-Sleep -Milliseconds 500
    $null = $wshell.AppActivate($peProc.Id)
    Start-Sleep -Milliseconds 500
    $wshell.SendKeys("% ")
    Start-Sleep -Milliseconds 200
    $wshell.SendKeys("x")
    $log.Add("INFO: Process Explorer launched — awaiting user review.")
    $peProc.WaitForExit()
    $log.Add("INFO: Process Explorer closed.")
} else {
    $log.Add("WARNING: procexp64.exe not found after extraction.")
}


# ==============================================================================

# ==============================================================================
#   HELPER FUNCTIONS (ENHANCED - v5.1)
# ==============================================================================

function Test-FileSignatureModified {
    param([string]$FilePath)
    try {
        $sig      = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            return @{ Modified = $true; Reason = "Invalid/missing signature: $($sig.Status)"; Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "None" } }
        }
        if ($fileInfo) {
            $diff = ($fileInfo.LastWriteTime - $fileInfo.CreationTime).TotalMinutes
            if ($diff -gt 10) {
                return @{ Modified = $true; Reason = "Binary modified $([math]::Round($diff))min after creation"; CreatedTime = $fileInfo.CreationTime; LastWriteTime = $fileInfo.LastWriteTime }
            }
        }
        return @{ Modified = $false }
    } catch { return @{ Modified = $false } }
}

function Test-ProcessCloaked {
    param([System.Diagnostics.Process]$Process)
    try {
        $path = $Process.Path
        if (-not $path) { return @{ Cloaked = $false } }
        $diskName = [System.IO.Path]::GetFileNameWithoutExtension($path).ToLower()
        $procName = $Process.ProcessName.ToLower()
        if ($diskName -ne $procName -and $diskName -notlike "*$procName*" -and $procName -notlike "*$diskName*") {
            return @{ Cloaked = $true; Reason = "Process name '$procName' does not match disk name '$diskName' — possible rename cloaking"; Path = $path }
        }
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
            if ($vi.OriginalFilename) {
                $orig = [System.IO.Path]::GetFileNameWithoutExtension($vi.OriginalFilename).ToLower()
                if ($orig -ne $procName -and $orig -notlike "*$procName*" -and $procName -notlike "*$orig*") {
                    return @{ Cloaked = $true; Reason = "OriginalFilename '$($vi.OriginalFilename)' does not match running name '$procName' — possible Resource Hacker modification"; Path = $path }
                }
            }
            # Flag if InternalName is blank or mismatched (sign of resource stripping)
            if ([string]::IsNullOrWhiteSpace($vi.InternalName) -and [string]::IsNullOrWhiteSpace($vi.FileDescription)) {
                return @{ Cloaked = $true; Reason = "Binary has no InternalName or FileDescription — likely resource-stripped"; Path = $path }
            }
        } catch {}
        return @{ Cloaked = $false }
    } catch { return @{ Cloaked = $false } }
}


# ==============================================================================
#   SECTION: ADVANCED PROCESS MONITORING (v5.1)
# ==============================================================================
Update-ScanProgress -Percent 76  
$log.Add("`n[SECTION: ADVANCED PROCESS MONITORING]")

$wmiProcesses  = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
$psProcesses   = Get-ProcessSnapshot
$psProcessIds  = $psProcesses | ForEach-Object { $_.Id }

# --- Hidden process detection: WMI vs PowerShell enumeration cross-check ---
$hiddenCount = 0
foreach ($wmiProc in $wmiProcesses) {
    if ($wmiProc.ProcessId -eq 0 -or $wmiProc.ProcessId -in $psProcessIds) { continue }

    $candidateText = "$($wmiProc.Name) $($wmiProc.CommandLine) $($wmiProc.ExecutablePath)"
    $isUserWritable = $candidateText -match 'appdata|\\temp\\|roaming|\\desktop\\|\\downloads\\'
    if (Test-SuspiciousIndicator $candidateText -BlacklistOnly:$false -or $isUserWritable) {
        $log.Add("FAIL: Suspicious hidden process detected -> $($wmiProc.Name) (PID: $($wmiProc.ProcessId)) | CmdLine: $($wmiProc.CommandLine)")
        $flags++; $hiddenCount++
    }
}
if ($hiddenCount -eq 0) { $log.Add("PASS: No suspicious hidden processes detected via WMI cross-check.") }

# --- Process cloaking: name mismatch + resource hacker detection ---
$cloakCount = 0
foreach ($proc in $psProcesses) {
    try {
        if (-not $proc.Path) { continue }

        # Signature check
        $sigCheck = Test-FileSignatureModified -FilePath $proc.Path
        if ($sigCheck.Modified) {
            $log.Add("WARN: Modified/unsigned process binary -> $($proc.ProcessName) | $($sigCheck.Reason) | Path: $($proc.Path)")
        }

        # Cloaking check (name mismatch + resource hacker)
        $cloakCheck = Test-ProcessCloaked -Process $proc
        if ($cloakCheck.Cloaked) {
            $log.Add("FAIL: Process cloaking detected -> $($proc.ProcessName) | $($cloakCheck.Reason)")
            $flags++; $cloakCount++
        }

        # File entropy anomaly: huge binary in temp paths
        $fi = [System.IO.FileInfo]$proc.Path
        if ($fi.Length -lt 5KB -and $proc.Path -match "temp|appdata") {
            $log.Add("WARN: Suspiciously small binary running from user path -> $($proc.ProcessName) ($($fi.Length) bytes) | $($proc.Path)")
        }
    } catch {}
}
if ($cloakCount -eq 0) { $log.Add("PASS: No process cloaking detected.") }

# --- Known process hider tool detection ---
$hiderPatterns = @(
    "winhider","processhider","process-pal","procpal","hideproc","ghostproc",
    "stealthproc","procshield","proccloak","hiddenproc","invisproc","palhide",
    "process-ghost","proc-hide","proc-cloak","proc-stealth","procmask","maskhide"
)
$hiderCount = 0
foreach ($proc in $psProcesses) {
    foreach ($hp in $hiderPatterns) {
        if ($proc.ProcessName -ilike "*$hp*") {
            $log.Add("FAIL: Process hiding tool active -> $($proc.ProcessName) (PID: $($proc.Id)) | $($proc.Path)")
            $flags++; $hiderCount++
        }
    }
}
# Also scan registry for known hider installs
foreach ($rp in @("HKLM:\SOFTWARE\WinHider","HKCU:\Software\WinHider","HKLM:\SOFTWARE\ProcessPal","HKCU:\Software\ProcessPal")) {
    if (Test-Path $rp) { $log.Add("FAIL: Process hider registry key detected -> $rp"); $flags++; $hiderCount++ }
}
if ($hiderCount -eq 0) { $log.Add("PASS: No process hiding tools detected.") }

# --- DLL injection / hooking heuristics on core system DLLs ---
$hookCount = 0
foreach ($proc in $psProcesses) {
    try {
        foreach ($module in $proc.Modules) {
            $mName = [System.IO.Path]::GetFileName($module.FileName).ToLower()
            if ($mName -match "^(ntdll|kernel32|kernelbase|user32|advapi32)\.dll$") {
                try {
                    $base  = $module.BaseAddress.ToInt64()
                    $entry = $module.EntryPointAddress.ToInt64()
                    # EntryPoint of 0 is normal for some system DLLs; a non-zero mismatch is suspicious
                    if ($entry -ne 0 -and $base -ne $entry -and ($entry -lt $base -or $entry -gt ($base + $module.ModuleMemorySize))) {
                        $log.Add("WARN: Possible hook/detour in $($proc.ProcessName) -> $mName (base: 0x$($base.ToString('X')) entry: 0x$($entry.ToString('X')))")
                        $hookCount++
                    }
                } catch {}
            }
        }
    } catch {}
}
if ($hookCount -eq 0) { $log.Add("PASS: No core DLL hooking anomalies detected.") }

# --- WMI CommandLine audit: injection-flavoured arguments ---
$wmiCmdCount = 0
foreach ($wmiProc in $wmiProcesses) {
    try {
        $cmd = $wmiProc.CommandLine
        if ($cmd -and $cmd -imatch "inject|bypass|exclude|hollow|shellcode|VirtualAlloc|WriteProcessMemory|CreateRemoteThread") {
            $log.Add("FAIL: Process with injection-flavoured command line -> $($wmiProc.Name) (PID: $($wmiProc.ProcessId))")
            $log.Add("      CMD: $($cmd.Substring(0,[Math]::Min(200,$cmd.Length)))")
            $flags++; $wmiCmdCount++
        }
    } catch {}
}
if ($wmiCmdCount -eq 0) { $log.Add("PASS: No injection-flavoured command lines detected.") }


# ==============================================================================
#   SECTION: NVIDIA HOOK DETECTION (v5.1)
# ==============================================================================
Update-ScanProgress -Percent 79  
$log.Add("`n[SECTION: NVIDIA HOOK DETECTION]")

$nvLegitRoots = @(
    "$env:ProgramFiles\NVIDIA Corporation",
    "${env:ProgramFiles(x86)}\NVIDIA Corporation",
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot\WinSxS"
) | ForEach-Object { if ($_) { $_.ToLower() } }

$nvProcessPatterns = @("nvidia*","nvcontainer*","nvdisplay*","nvtelemetry*","nvspcap*","nvsphelper*","nvcplui*")
$nvProcs = foreach ($pat in $nvProcessPatterns) {
    Get-Process -Name ($pat -replace '\*','') -ErrorAction SilentlyContinue
}

$nvFlagCount = 0
foreach ($proc in $nvProcs) {
    if (-not $proc) { continue }
    try {
        foreach ($module in $proc.Modules) {
            $mPath = $module.FileName
            if (-not $mPath) { continue }
            $mLow = $mPath.ToLower()

            $isLegit = ($nvLegitRoots | Where-Object { $_ -and $mLow.StartsWith($_) }).Count -gt 0

            if (-not $isLegit) {
                # Extra check: is the DLL signed by NVIDIA or Microsoft?
                $sig = Get-AuthenticodeSignature $mPath -ErrorAction SilentlyContinue
                $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
                if ($sig.Status -ne "Valid" -or $signer -notmatch "NVIDIA|Microsoft") {
                    $log.Add("FAIL: Suspicious/unsigned DLL injected into NVIDIA process -> $($proc.ProcessName) | $mPath | Signer: $signer | Status: $($sig.Status)")
                    $flags++; $nvFlagCount++
                } else {
                    $log.Add("WARN: Non-standard path DLL in NVIDIA process (signed OK) -> $($proc.ProcessName) | $mPath | $signer")
                }
            }
        }

        # Check for NVIDIA process running from unexpected location
        if ($proc.Path) {
            $pLow = $proc.Path.ToLower()
            $isLegitPath = ($nvLegitRoots | Where-Object { $_ -and $pLow.StartsWith($_) }).Count -gt 0
            if (-not $isLegitPath) {
                $log.Add("FAIL: NVIDIA process running from unexpected path -> $($proc.ProcessName) | $($proc.Path)")
                $flags++; $nvFlagCount++
            }
        }
    } catch {}
}

# Scan for known NVIDIA hook DLLs by name in all processes
$nvHookDllNames = @("nvcuda_hook","nvcuda_patch","nvapi_hook","nvd3d_hook","nvapi64_hook","nv_hook","nvhook","nvidia_hook","nvpatch","nvbypass")
foreach ($proc in $psProcesses) {
    try {
        foreach ($module in $proc.Modules) {
            $mName = [System.IO.Path]::GetFileName($module.FileName).ToLower()
            foreach ($hookDll in $nvHookDllNames) {
                if ($mName -like "*$hookDll*") {
                    $log.Add("FAIL: Known NVIDIA hook DLL detected in $($proc.ProcessName) -> $($module.FileName)")
                    $flags++; $nvFlagCount++
                }
            }
        }
    } catch {}
}

if ($nvFlagCount -eq 0) { $log.Add("PASS: No NVIDIA hook or injection indicators detected.") }


# ==============================================================================
#   SECTION: BROWSER HISTORY ANALYSIS (v5.1)
# ==============================================================================
Update-ScanProgress -Percent 82 
$log.Add("`n[SECTION: BROWSER HISTORY ANALYSIS]")

$browserHistoryTerms = @($cheatBlacklist | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
$browserHistoryRegex = [regex]::new((($browserHistoryTerms | Sort-Object Length -Descending | ForEach-Object { [regex]::Escape($_) }) -join '|'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Get-HistoryHits {
    param([byte[]]$Bytes)
    $hitSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $null -eq $browserHistoryRegex) { return @() }

    $content = [System.Text.Encoding]::GetEncoding(28591).GetString($Bytes)
    foreach ($m in $browserHistoryRegex.Matches($content)) {
        if ($m.Success -and -not [string]::IsNullOrWhiteSpace($m.Value)) {
            [void]$hitSet.Add($m.Value)
        }
    }
    return @($hitSet | Sort-Object -Unique)
}

function Search-ChromiumHistory {
    param([string]$BrowserName, [string]$HistoryPath)
    if (-not (Test-Path $HistoryPath)) { return }
    $tmp = $null
    try {
        $tmp = Join-Path $env:TEMP ("bhist_{0}.db" -f ([Guid]::NewGuid().ToString('N')))
        Copy-Item $HistoryPath $tmp -Force -ErrorAction Stop
        if (-not (Test-Path $tmp)) { return }

        $bytes = [System.IO.File]::ReadAllBytes($tmp)
        $hits  = Get-HistoryHits -Bytes $bytes

        foreach ($hit in $hits) {
            $log.Add("FAIL: Blacklisted cheat term found in $BrowserName history -> $hit")
            $script:flags++
        }
        $log.Add("INFO: $BrowserName history scan complete.")
    } catch {
        $log.Add("INFO: $BrowserName history scan skipped — $($_.Exception.Message)")
    } finally {
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Search-FirefoxHistory {
    param([string]$ProfilePath)
    if (-not (Test-Path $ProfilePath)) { return }
    $db  = Join-Path $ProfilePath "places.sqlite"
    if (-not (Test-Path $db)) { return }
    $tmp = $null
    try {
        $tmp = Join-Path $env:TEMP ("ffhist_{0}.db" -f ([Guid]::NewGuid().ToString('N')))
        Copy-Item $db $tmp -Force -ErrorAction Stop
        if (-not (Test-Path $tmp)) { return }

        $bytes = [System.IO.File]::ReadAllBytes($tmp)
        $hits  = Get-HistoryHits -Bytes $bytes

        foreach ($hit in $hits) {
            $log.Add("FAIL: Blacklisted cheat term found in Firefox history -> $hit")
            $script:flags++
        }
        $log.Add("INFO: Firefox history scan complete.")
    } catch {
        $log.Add("INFO: Firefox history scan skipped — $($_.Exception.Message)")
    } finally {
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-BrowserActuallyUsed {
    param(
        [string]$ProcessName,
        [string[]]$HistoryFiles
    )
    try {
        if ($ProcessName -and (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1)) { return $true }
    } catch {}
    foreach ($hf in $HistoryFiles) {
        if ($hf -and (Test-Path $hf)) {
            try {
                $item = Get-Item $hf -ErrorAction Stop
                if ($item.Length -gt 0 -and $item.LastWriteTime -gt (Get-Date).AddDays(-120)) { return $true }
            } catch {}
        }
    }
    return $false
}

$scannedBrowserLabels = New-Object System.Collections.Generic.List[string]

# Chrome (all profiles)
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
if (Test-Path $chromePath) {
    $chromeProfiles = @(Get-ChildItem $chromePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" })
    $chromeHistories = @($chromeProfiles | ForEach-Object { Join-Path $_.FullName "History" })
    if (Test-BrowserActuallyUsed -ProcessName 'chrome' -HistoryFiles $chromeHistories) {
        foreach ($profile in $chromeProfiles) { Search-ChromiumHistory -BrowserName "Chrome ($($profile.Name))" -HistoryPath (Join-Path $profile.FullName "History") }
        $scannedBrowserLabels.Add('Chrome') | Out-Null
    }
}

# Edge (all profiles)
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
if (Test-Path $edgePath) {
    $edgeProfiles = @(Get-ChildItem $edgePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" })
    $edgeHistories = @($edgeProfiles | ForEach-Object { Join-Path $_.FullName "History" })
    if (Test-BrowserActuallyUsed -ProcessName 'msedge' -HistoryFiles $edgeHistories) {
        foreach ($profile in $edgeProfiles) { Search-ChromiumHistory -BrowserName "Edge ($($profile.Name))" -HistoryPath (Join-Path $profile.FullName "History") }
        $scannedBrowserLabels.Add('Edge') | Out-Null
    }
}

# Brave
$bravePath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
if (Test-Path $bravePath) {
    $braveProfiles = @(Get-ChildItem $bravePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" })
    $braveHistories = @($braveProfiles | ForEach-Object { Join-Path $_.FullName "History" })
    if (Test-BrowserActuallyUsed -ProcessName 'brave' -HistoryFiles $braveHistories) {
        foreach ($profile in $braveProfiles) { Search-ChromiumHistory -BrowserName "Brave ($($profile.Name))" -HistoryPath (Join-Path $profile.FullName "History") }
        $scannedBrowserLabels.Add('Brave') | Out-Null
    }
}

# Opera / Opera GX
$operaEntries = @(
    @{ Label = 'Opera Stable'; Process='opera'; Path="$env:APPDATA\Opera Software\Opera Stable" },
    @{ Label = 'Opera GX'; Process='opera'; Path="$env:APPDATA\Opera Software\Opera GX Stable" }
)
foreach ($op in $operaEntries) {
    if (Test-Path $op.Path) {
        $historyPath = Join-Path $op.Path 'History'
        if (Test-BrowserActuallyUsed -ProcessName $op.Process -HistoryFiles @($historyPath)) {
            Search-ChromiumHistory -BrowserName $op.Label -HistoryPath $historyPath
            $scannedBrowserLabels.Add($op.Label) | Out-Null
        }
    }
}

# Vivaldi
$vivaldiPath = "$env:LOCALAPPDATA\Vivaldi\User Data"
if (Test-Path $vivaldiPath) {
    $vivaldiProfiles = @(Get-ChildItem $vivaldiPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" })
    $vivaldiHistories = @($vivaldiProfiles | ForEach-Object { Join-Path $_.FullName "History" })
    if (Test-BrowserActuallyUsed -ProcessName 'vivaldi' -HistoryFiles $vivaldiHistories) {
        foreach ($profile in $vivaldiProfiles) { Search-ChromiumHistory -BrowserName "Vivaldi ($($profile.Name))" -HistoryPath (Join-Path $profile.FullName "History") }
        $scannedBrowserLabels.Add('Vivaldi') | Out-Null
    }
}

# Firefox (all profiles)
$ffBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $ffBase) {
    $ffProfiles = @(Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue)
    $ffHistories = @($ffProfiles | ForEach-Object { Join-Path $_.FullName 'places.sqlite' })
    if (Test-BrowserActuallyUsed -ProcessName 'firefox' -HistoryFiles $ffHistories) {
        foreach ($profile in $ffProfiles) { Search-FirefoxHistory -ProfilePath $profile.FullName }
        $scannedBrowserLabels.Add('Firefox') | Out-Null
    }
}

if ($scannedBrowserLabels.Count -gt 0) {
    $log.Add("INFO: Browser history scanned for active/used browsers only -> $($scannedBrowserLabels -join ', ')")
} else {
    $log.Add("INFO: No active/used browser profiles met the scan criteria.")
}

# Also check browser typed URLs in registry
$typedUrlKey = "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"
if (Test-Path $typedUrlKey) {
    (Get-ItemProperty $typedUrlKey -ErrorAction SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -like "url*" } |
        ForEach-Object {
            $hits = Get-HistoryHits -Bytes ([System.Text.Encoding]::UTF8.GetBytes($_.Value.ToString()))
            foreach ($hit in $hits) {
                $log.Add("FAIL: Typed URL contains blacklisted cheat term -> $hit")
                $script:flags++
            }
        }
}

# --- PowerShell History: Defender bypass commands ---
$mpCmdPatterns = @("Set-MpPreference","Add-MpPreference","DisableRealtimeMonitoring","ExclusionPath","ExclusionProcess","DisableBehaviorMonitoring","DisableIOAVProtection","DisableScriptScanning")
$psHistPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistPath) {
    try {
        $histLines = Get-Content $psHistPath -ErrorAction SilentlyContinue
        foreach ($hLine in $histLines) {
            foreach ($mpPat in $mpCmdPatterns) {
                if ($hLine -imatch [regex]::Escape($mpPat)) {
                    $log.Add("FAIL: PowerShell history contains Defender manipulation -> $hLine")
                    $flags++; break
                }
            }
        }
    } catch { $log.Add("INFO: Could not read PowerShell history.") }
} else { $log.Add("INFO: No PowerShell console history file found.") }

# --- Registry: recently modified Defender exclusion keys (last 7 days) ---
$exclRegKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths"
)
foreach ($exKey in $exclRegKeys) {
    if (Test-Path $exKey) {
        try {
            $regItem = Get-Item $exKey -ErrorAction SilentlyContinue
            $valNames = $regItem.GetValueNames() | Where-Object { $_ -ne "" }
            if ($valNames.Count -gt 0) {
                $keyLabel = $exKey -replace ".*Exclusions\\", "Exclusion "
                $log.Add("FAIL: Defender $keyLabel registry entries present — possible exclusion injector residue.")
                foreach ($vn in $valNames) { $log.Add("  REGISTRY EXCLUSION: $vn"); $flags++ }
            }
        } catch {}
    }
}

# --- File scan: scripts in user paths that contain Defender bypass commands ---
$bypassScriptPaths = @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads","$env:USERPROFILE\Documents","$env:APPDATA","$env:TEMP")
$bypassExts = @("*.ps1","*.bat","*.cmd","*.vbs")
$bypassTerms = @("Set-MpPreference","Add-MpPreference","DisableRealtimeMonitoring","ExclusionPath","DisableBehaviorMonitoring","Add-MpPreference -ExclusionPath")
$bypassScriptCutoff = (Get-Date).AddDays(-14)
foreach ($bsp in $bypassScriptPaths) {
    if (-not (Test-Path $bsp)) { continue }
    foreach ($ext in $bypassExts) {
        try {
            $bFiles = Get-ChildItem $bsp -Filter $ext -Recurse -ErrorAction SilentlyContinue |
                      Where-Object { $_.LastWriteTime -gt $bypassScriptCutoff } | Select-Object -First 30
            foreach ($bf in $bFiles) {
                try {
                    $bContent = Get-Content $bf.FullName -Raw -ErrorAction SilentlyContinue
                    foreach ($bt in $bypassTerms) {
                        if ($bContent -imatch [regex]::Escape($bt)) {
                            $log.Add("FAIL: Script file contains Defender bypass command [$bt] -> $($bf.FullName)")
                            $flags++; break
                        }
                    }
                } catch {}
            }
        } catch {}
    }
}

# Temp/Downloads execution detection (exclusion injectors often run from here)
$suspectedExecPaths = @($env:TEMP,$env:TMP,"$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:PUBLIC\Downloads")
$tempExecCount = 0
foreach ($proc in $psProcesses) {
    try {
        if (-not $proc.Path) { continue }
        $isSystem = $proc.Path -match "^[A-Za-z]:\\(Windows|Program Files)"
        if (-not $isSystem) {
            foreach ($sp in $suspectedExecPaths) {
                if ($proc.Path -like "$sp*") {
                    $log.Add("WARN: Process executing from user/temp path -> $($proc.ProcessName) | $($proc.Path)")
                    $tempExecCount++; break
                }
            }
        }
    } catch {}
}
if ($tempExecCount -eq 0) { $log.Add("PASS: No processes detected executing from temp/download paths.") }

# Check for temp-path DLL loads across all processes
$tempDllCount = 0
foreach ($proc in $psProcesses) {
    try {
        foreach ($module in $proc.Modules) {
            $mPath = $module.FileName
            if (-not $mPath) { continue }
            foreach ($tp in @($env:TEMP,$env:TMP)) {
                if ($mPath -like "$tp*") {
                    $log.Add("FAIL: DLL loaded from temp directory -> Process: $($proc.ProcessName) | DLL: $mPath")
                    $flags++; $tempDllCount++; break
                }
            }
        }
    } catch {}
}
if ($tempDllCount -eq 0) { $log.Add("PASS: No temp-directory DLL loads detected.") }


# ==============================================================================
#   SECTION: WIN32 API INLINE HOOK DETECTION (v5.1)
#   Detects JMP/trampoline hooks placed on critical Windows APIs:
#   GetWindowDisplayAffinity (screen-capture hiding), Module32FirstW/NextW
#   (process hiding), ReadProcessMemory, NtQuerySystemInformation, etc.
# ==============================================================================
Update-ScanProgress -Percent 91 
$log.Add("`n[SECTION: WIN32 API INLINE HOOK DETECTION]")

$hookTypeLoaded = $false
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32HookChecker {
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr LoadLibraryA(string lpLibFileName);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    public static byte[] GetFunctionPrologue(string module, string function, int byteCount) {
        IntPtr hMod = LoadLibraryA(module);
        if (hMod == IntPtr.Zero) return null;
        IntPtr addr = GetProcAddress(hMod, function);
        if (addr == IntPtr.Zero) return null;
        byte[] buf = new byte[byteCount];
        int read = 0;
        if (ReadProcessMemory(GetCurrentProcess(), addr, buf, byteCount, out read) && read > 0)
            return buf;
        return null;
    }
}
"@ -ErrorAction Stop
    $hookTypeLoaded = $true
} catch {
    $log.Add("WARN: Hook checker type compilation failed — $($_.Exception.Message)")
}

function Detect-InlineHook {
    param([string]$ModuleName, [string]$FunctionName)
    try {
        $bytes = [Win32HookChecker]::GetFunctionPrologue($ModuleName, $FunctionName, 8)
        if ($null -eq $bytes) { return $null }
        $hex = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ' '
        if ($bytes[0] -eq 0xE9)                              { return [PSCustomObject]@{ Hooked=$true;  HookType="JMP rel32 (E9)";           Prologue=$hex } }
        if ($bytes[0] -eq 0xEB)                              { return [PSCustomObject]@{ Hooked=$true;  HookType="JMP short (EB)";            Prologue=$hex } }
        if ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0x25)     { return [PSCustomObject]@{ Hooked=$true;  HookType="JMP [rip+rel] (FF 25)";    Prologue=$hex } }
        if ($bytes[0] -eq 0x48 -and $bytes[1] -eq 0xB8)     { return [PSCustomObject]@{ Hooked=$true;  HookType="MOV RAX,imm64 (48 B8)";    Prologue=$hex } }
        if ($bytes[0] -eq 0xCC)                              { return [PSCustomObject]@{ Hooked=$true;  HookType="INT3 breakpoint (CC)";      Prologue=$hex } }
        if ($bytes[0] -eq 0x90 -and $bytes[1] -eq 0x90 -and $bytes[2] -eq 0x90) {
                                                               return [PSCustomObject]@{ Hooked=$true;  HookType="NOP sled (90 90 90)";       Prologue=$hex } }
        return [PSCustomObject]@{ Hooked=$false; Prologue=$hex }
    } catch { return $null }
}

$apiHookTargets = @(
    # Screen-capture / display affinity hooks (hide window from recorders/OBS)
    @{ Module="user32.dll";   Function="GetWindowDisplayAffinity"; Severity="FAIL"; Reason="Screen-capture hiding hook — window content hidden from recorders" },
    @{ Module="user32.dll";   Function="SetWindowDisplayAffinity"; Severity="FAIL"; Reason="Screen-capture affinity manipulation hook" },
    # Process & module enumeration hooks (Module32First/Next hide DLLs/processes from toolhelp32)
    @{ Module="kernel32.dll"; Function="Module32FirstW";           Severity="FAIL"; Reason="Module/process enumeration hook — hides injected DLLs from toolhelp32" },
    @{ Module="kernel32.dll"; Function="Module32NextW";            Severity="FAIL"; Reason="Module/process enumeration hook — hides injected DLLs from toolhelp32" },
    @{ Module="kernel32.dll"; Function="Process32FirstW";          Severity="FAIL"; Reason="Process enumeration hook — hides processes from toolhelp32 snapshot" },
    @{ Module="kernel32.dll"; Function="Process32NextW";           Severity="FAIL"; Reason="Process enumeration hook — hides processes from toolhelp32 snapshot" },
    @{ Module="kernel32.dll"; Function="CreateToolhelp32Snapshot"; Severity="WARN"; Reason="Toolhelp snapshot hook — may filter process/module results" },
    # Memory/process access hooks
    @{ Module="kernel32.dll"; Function="OpenProcess";              Severity="WARN"; Reason="Process access hook — may block external analysis" },
    @{ Module="kernel32.dll"; Function="ReadProcessMemory";        Severity="FAIL"; Reason="Memory reading hook — blocks process inspection tools" },
    @{ Module="kernel32.dll"; Function="WriteProcessMemory";       Severity="FAIL"; Reason="Memory writing hook" },
    # NT-layer hooks (deeper stealth / anti-detection)
    @{ Module="ntdll.dll";    Function="NtQuerySystemInformation"; Severity="FAIL"; Reason="NT system-info hook — hides processes from all enumeration" },
    @{ Module="ntdll.dll";    Function="NtOpenProcess";            Severity="WARN"; Reason="NT process-open hook" },
    @{ Module="ntdll.dll";    Function="NtReadVirtualMemory";      Severity="FAIL"; Reason="NT memory read hook" },
    @{ Module="ntdll.dll";    Function="NtQueryInformationProcess"; Severity="WARN"; Reason="NT process info hook" }
)

$apiHookCount = 0
if ($hookTypeLoaded) {
    foreach ($target in $apiHookTargets) {
        $hookResult = Detect-InlineHook -ModuleName $target.Module -FunctionName $target.Function
        if ($null -eq $hookResult) {
            $log.Add("INFO: Hook check skipped — $($target.Module)!$($target.Function) (could not read prologue)")
            continue
        }
        if ($hookResult.Hooked) {
            $log.Add("$($target.Severity): Inline hook on $($target.Module)!$($target.Function) — $($target.Reason)")
            $log.Add("      Hook type: $($hookResult.HookType) | First 8 bytes: $($hookResult.Prologue)")
            $flags++; $apiHookCount++
        } else {
            $log.Add("PASS: $($target.Module)!$($target.Function) — prologue intact [$($hookResult.Prologue)]")
        }
    }
    if ($apiHookCount -eq 0) { $log.Add("PASS: No Win32 API inline hooks detected on critical functions.") }
} else {
    $log.Add("WARN: Win32 API hook detection skipped — P/Invoke type load failed.")
}


# --- ADDED DETECTIONS ---

# PROCESS SCAN
Update-ScanProgress -Percent 93 
$log.Add("`n[SECTION: PROCESS SCAN]")
$processes = Get-ProcessSnapshot | Select-Object Name, Path -ErrorAction SilentlyContinue
foreach ($proc in $processes) {
    if (Test-SuspiciousIndicator $proc.Name) {
            $log.Add("FAIL: Suspicious Process -> $($proc.Name)")
            $flags++
        }
}

# MODULE SCAN
Update-ScanProgress -Percent 94  
$log.Add("`n[SECTION: MODULE SCAN]")
foreach ($proc in Get-ProcessSnapshot) {
    try {
        foreach ($mod in $proc.Modules) {
            if ($mod.FileName -like "*temp*" -or $mod.FileName -like "*appdata*") {
                $log.Add("WARN: Suspicious Module in $($proc.Name) -> $($mod.FileName)")
                $flags++
            }
        }
    } catch {}
}

# STARTUP CHECK
Update-ScanProgress -Percent 95 
$log.Add("`n[SECTION: STARTUP CHECK]")
$startupPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $startupPaths) {
    try {
        $items = Get-ItemProperty -Path $path
        foreach ($prop in $items.PSObject.Properties) {
            if (Test-SuspiciousIndicator ([string]$prop.Value)) {
                $log.Add("FAIL: Startup Entry -> $($prop.Name)")
                $flags++
            }
        }
    } catch {}
}

# FILE SYSTEM SCAN
Update-ScanProgress -Percent 96  
$log.Add("`n[SECTION: FILE SYSTEM SCAN]")
$paths = @("$env:APPDATA","$env:LOCALAPPDATA","$env:TEMP")
foreach ($path in $paths) {
    try {
        Get-ChildItem $path -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 500 | ForEach-Object {
            if (Test-BlacklistTerm $_.Name) {
                $log.Add("FAIL: Suspicious File -> $($_.FullName)")
                $flags++
            }
        }
    } catch {}
}


# ================================
# ADVANCED FILE EXPLORER SCAN
# ================================
Update-ScanProgress -Percent 97 
$log.Add("`n[SECTION: DEEP FILE EXPLORER SCAN]")
$drives = Get-PSDrive -PSProvider FileSystem

foreach ($drive in $drives) {
    try {
        Get-ChildItem ($drive.Root) -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 750 | ForEach-Object {
            if (Test-BlacklistTerm $_.Name) {
                $log.Add("FAIL: Found Cheat Artifact -> $($_.FullName)")
                $flags++
            }
        }
    } catch {}
}

# ================================
# MACRO / SCRIPT DETECTION
# ================================
Update-ScanProgress -Percent 98 
$log.Add("`n[SECTION: MACRO / SCRIPT SCAN]")

$macroPaths = @(
    "$env:APPDATA\Logitech",
    "$env:LOCALAPPDATA\Temp",
    "$env:APPDATA\AutoHotkey"
)

foreach ($path in $macroPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 500 | ForEach-Object {
            if ($_.Extension -in ".ahk",".lua",".txt",".cfg") {
                try {
                    $content = Get-Content $_.FullName -ErrorAction SilentlyContinue
                    if ($content -match "aim|recoil|macro|script") {
                        $log.Add("WARN: Suspicious Macro Script -> $($_.FullName)")
                        $flags++
                    }
                } catch {}
            }
        }
    }
}

# ================================
# BAM (Background Activity Monitor) FIX
# ================================
Update-ScanProgress -Percent 99 
$log.Add("`n[SECTION: BAM FORENSICS]")
try {
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $bam = Get-ChildItem $bamPath -Recurse -ErrorAction SilentlyContinue
    foreach ($entry in $bam) {
        if (Test-SuspiciousIndicator $entry.Name) {
                $log.Add("FAIL: BAM Execution Artifact -> $($entry.Name)")
                $flags++
            }
    }
} catch {
    $log.Add("INFO: BAM access failed")
}

# ================================
# DEBUGGER / TOOL DETECTION
# ================================
Update-ScanProgress -Percent 99 
$log.Add("`n[SECTION: DEBUG DETECTION]")

$debugTools = @("wireshark","fiddler","processhacker","ida","x64dbg","ollydbg")

foreach ($proc in Get-ProcessSnapshot) {
    foreach ($tool in $debugTools) {
        if ($proc.Name -like "*$tool*") {
            $log.Add("FAIL: Debugging tool detected -> $($proc.Name)")
            $flags++
        }
    }
}

# ================================
# ADVANCED MEMORY PATTERN SCANNING
# ================================
Update-ScanProgress -Percent 99 
$log.Add("`n[SECTION: ADVANCED MEMORY SCAN]")

foreach ($proc in Get-ProcessSnapshot) {
    try {
        # Scan modules (in-memory DLLs)
        foreach ($mod in $proc.Modules) {
            foreach ($black in $cheatBlacklist) {
                if ($mod.ModuleName -like "*$black*") {
                    $log.Add("FAIL: Memory Module Match -> $($proc.Name) : $($mod.ModuleName)")
                    $flags++
                }
            }
        }

        # Scan binary content (string heuristic)
        if ($proc.Path -and (Test-Path $proc.Path)) {
            $bytes = [System.IO.File]::ReadAllBytes($proc.Path)
            $textData = [System.Text.Encoding]::ASCII.GetString($bytes)

            foreach ($black in $cheatBlacklist) {
                if ($textData -match $black) {
                    $log.Add("WARN: Binary string match -> $($proc.Path)")
                    $flags++
                    break
                }
            }
        }

    } catch {}
}


function Send-AuditWebhook {
    param(
        [string]$Url,
        [string]$LogFilePath,
        [int]$FlagCount,
        [string]$MachineName,
        [string]$UserName
    )

    $colour      = if ($FlagCount -gt 0) { 15158332 } else { 5763719 }
    $statusEmoji = if ($FlagCount -gt 0) { "⚠️" } else { "✅" }
    $statusText  = if ($FlagCount -gt 0) { "Flagged" } else { "Clean" }
    $statusLine  = if ($FlagCount -gt 0) { "⚠️ **Flagged scan** with **$FlagCount** issue(s) found." } else { "✅ **Clean scan** with no flags found." }
    $scanTime    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fileName    = [System.IO.Path]::GetFileName($LogFilePath)
    $logLines    = 0
    try { $logLines = (Get-Content -LiteralPath $LogFilePath -ErrorAction Stop | Measure-Object -Line).Lines } catch {}

    $payloadJson = [PSCustomObject]@{
        username   = "SubRec Policy"
        avatar_url = "https://cdn.discordapp.com/embed/avatars/0.png"
        embeds     = @(
            [PSCustomObject]@{
                title       = "🛡️ Sub's Recording Policy Report"
                description = "$statusLine`n`n📎 Full audit report attached below."
                color       = $colour
                fields      = @(
                    [PSCustomObject]@{ name = "💻 PC";           value = if ($MachineName) { $MachineName } else { "Unknown" }; inline = $true  }
                    [PSCustomObject]@{ name = "👤 User";         value = if ($UserName) { $UserName } else { "Unknown" }; inline = $true  }
                    [PSCustomObject]@{ name = "📌 Result";       value = "$statusEmoji $statusText"; inline = $true  }
                    [PSCustomObject]@{ name = "🚩 Flags";        value = "$FlagCount"; inline = $true  }
                    [PSCustomObject]@{ name = "📝 Log Lines";    value = "$logLines"; inline = $true  }
                    [PSCustomObject]@{ name = "🕒 Scan Time";    value = $scanTime; inline = $true  }
                    [PSCustomObject]@{ name = "📄 Attachment";   value = $fileName; inline = $false }
                )
                footer = [PSCustomObject]@{ text = "Sub's Recording Policy • v5.1" }
                timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
        )
        attachments = @(
            [PSCustomObject]@{
                id = 0
                filename = $fileName
            }
        )
    } | ConvertTo-Json -Depth 12 -Compress

    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($LogFilePath)
        $boundary  = [System.Guid]::NewGuid().ToString('N')
        $CRLF      = "`r`n"

        $payloadPart = "--$boundary$CRLF" +
                       "Content-Disposition: form-data; name=`"payload_json`"$CRLF$CRLF" +
                       $payloadJson + $CRLF
        $filePartHeader = "--$boundary$CRLF" +
                          "Content-Disposition: form-data; name=`"files[0]`"; filename=`"$fileName`"$CRLF" +
                          "Content-Type: text/plain$CRLF$CRLF"
        $bodyEnd = "$CRLF--$boundary--$CRLF"

        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadPart)
        $fileHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($filePartHeader)
        $endBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyEnd)

        $ms = New-Object System.IO.MemoryStream
        $ms.Write($payloadBytes, 0, $payloadBytes.Length)
        $ms.Write($fileHeaderBytes, 0, $fileHeaderBytes.Length)
        $ms.Write($fileBytes, 0, $fileBytes.Length)
        $ms.Write($endBytes, 0, $endBytes.Length)
        $bodyArr = $ms.ToArray()
        $ms.Dispose()

        Invoke-RestMethod -Uri $Url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyArr -ErrorAction Stop | Out-Null
        return @($true, "OK")
    } catch {
        return @($false, "Webhook failed: $($_.Exception.Message)")
    }
}

function Compress-LogLines {
    param([System.Collections.Generic.List[string]]$Lines)
    $result = New-Object System.Collections.Generic.List[string]
    $last = $null
    $blankStreak = 0
    foreach ($line in $Lines) {
        $normalized = if ($null -eq $line) { "" } else { [string]$line }
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            $blankStreak++
            if ($blankStreak -gt 1) { continue }
        } else {
            $blankStreak = 0
        }
        if ($null -ne $last -and $normalized -eq $last) { continue }
        $result.Add($normalized) | Out-Null
        $last = $normalized
    }
    return $result
}

function Shorten-DisplayPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path
    foreach ($root in @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot)) {
        if ($root -and $p.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ('...' + $p.Substring($root.Length))
        }
    }
    return $p
}

function Show-PAHWindow {
    $launcherPath = Join-Path $env:TEMP ("subrec_pah_{0}.ps1" -f ([Guid]::NewGuid().ToString('N')))
    try {
        $launcher = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-ProcessActiveHistory {
    `$form = New-Object Windows.Forms.Form
    `$form.Text = "Process Active History"
    `$form.WindowState = 'Maximized'
    `$form.MinimumSize = New-Object Drawing.Size(800, 600)
    `$form.StartPosition = "CenterScreen"
    `$form.BackColor = [Drawing.Color]::White
    `$form.Topmost = `$true

    `$listBox = New-Object Windows.Forms.ListBox
    `$listBox.Dock = 'Fill'
    `$listBox.Font = New-Object Drawing.Font("Consolas", 10)
    `$listBox.BackColor = [Drawing.Color]::White
    `$listBox.ForeColor = [Drawing.Color]::Black
    `$form.Controls.Add(`$listBox)

    `$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        foreach (`$p in (Get-Process | Where-Object { `$_.MainWindowTitle -or `$_.ProcessName })) {
            if (`$p.ProcessName -and -not `$seen.Contains(`$p.ProcessName)) {
                [void]`$seen.Add(`$p.ProcessName)
                `$stamp = Get-Date -Format "HH:mm:ss"
                [void]`$listBox.Items.Add("[`$stamp] Opened: `$(`$p.ProcessName)")
            }
        }
    } catch {}

    `$timer = New-Object Windows.Forms.Timer
    `$timer.Interval = 2000
    `$timer.Add_Tick({
        try {
            `$procs = Get-Process | Where-Object { `$_.MainWindowTitle -or `$_.ProcessName }
            foreach (`$p in `$procs) {
                `$name = `$p.ProcessName
                if (`$name -and -not `$seen.Contains(`$name)) {
                    [void]`$seen.Add(`$name)
                    `$stamp = Get-Date -Format "HH:mm:ss"
                    [void]`$listBox.Items.Add("[`$stamp] Opened: `$name")
                }
            }
        } catch {}
    })
    `$timer.Start()
    `$form.Add_Shown({ `$form.Activate() })
    `$form.Add_FormClosing({ `$timer.Stop(); `$timer.Dispose() })
    [void] `$form.ShowDialog()
}

Show-ProcessActiveHistory
Remove-Item -LiteralPath '$launcherPath' -Force -ErrorAction SilentlyContinue
"@
        Set-Content -Path $launcherPath -Value $launcher -Encoding UTF8 -Force
        $pwsh = (Get-Command powershell.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        if (-not $pwsh) { $pwsh = (Get-Command pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source }
        if ($pwsh) {
            Start-Process -FilePath $pwsh -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-STA','-File', $launcherPath) -WindowStyle Normal | Out-Null
            $log.Add("INFO: PAH launched near end of scan.")
        } else {
            $log.Add("INFO: PAH skipped — no PowerShell host found.")
        }
    } catch {
        $log.Add("INFO: PAH failed to launch — $($_.Exception.Message)")
    }
}

# ==============================================================================
#   FINAL SUMMARY + LOG WRITE + WEBHOOK
# ==============================================================================
# ==============================================================================
$log.Add("`n[SUMMARY]")
$log.Add("PC Name       : $($env:COMPUTERNAME)")
$log.Add("User          : $($env:USERNAME)")
$log.Add("Total Flags   : $flags")

# ==============================================================================
#   SECTION: PUBLIC FORENSIC HEURISTICS
# ==============================================================================
Update-ScanProgress -Percent 96
$log.Add("`n[SECTION: PUBLIC FORENSIC HEURISTICS]")

function Test-HiddenOrUnicodeName {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return [regex]::IsMatch($Text, '[\x00-\x1F\x7F\u200B-\u200F\u202A-\u202E\u2060\uFEFF]')
}

# Suspicious URL protocols / shell handlers
try {
    $protocolRoots = @("HKCU:\Software\Classes", "HKLM:\SOFTWARE\Classes")
    $checkedHandlers = 0
    $suspiciousHandlers = New-Object System.Collections.Generic.List[object]
    $userWritableHandlers = New-Object System.Collections.Generic.List[object]

    $knownBenignProtocols = @(
        'discord','discord-562286213059444737','roblox','roblox-player','roblox-studio','roblox-studio-auth',
        'zoommtg','zoomus','zoommeeting.sip','zoomphonecall','zoompbx.im','zoompbx.zoomphonecall',
        'tg','tonsite','telegram','spotify','vscode','cursor','cursor-insiders','opera','operastable',
        'odopen','grvopen','msonedrivesyncserviceclient','onedrive','medal','modrinth','lunarclient',
        'framer-app','proton-inbox','wispr-flow','bstsrvs','capcut'
    )

    foreach ($root in $protocolRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($sub in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            try {
                $scheme = $sub.PSChildName
                if ([string]::IsNullOrWhiteSpace($scheme)) { continue }
                if ($scheme -eq '*' -or $scheme.StartsWith('.')) { continue }
                if ($scheme -notmatch '^[a-zA-Z][a-zA-Z0-9+\-\.]{1,80}$') { continue }

                $keyPath = $sub.PSPath
                $hasProtocol = $null -ne (Get-ItemProperty -Path $keyPath -Name "URL Protocol" -ErrorAction SilentlyContinue)."URL Protocol"
                if (-not $hasProtocol) { continue }

                $cmdKey = Join-Path $sub.PSPath "shell\open\command"
                $cmd = (Get-ItemProperty -Path $cmdKey -ErrorAction SilentlyContinue)."(default)"
                if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
                $checkedHandlers++

                $isUserWritable = $cmd -imatch 'appdata|\\temp\\|\\users\\[^\\]+\\downloads\\|\\users\\[^\\]+\\desktop\\'
                $isBenignScheme = $knownBenignProtocols -contains $scheme.ToLower()
                $hasCheatSignal = Test-BlacklistTerm "$scheme $cmd"

                if ($hasCheatSignal) {
                    $suspiciousHandlers.Add([pscustomobject]@{
                        Scheme = $scheme
                        Command = $cmd
                    }) | Out-Null
                    $flags++
                    continue
                }

                if ($isUserWritable -and -not $isBenignScheme) {
                    $userWritableHandlers.Add([pscustomobject]@{
                        Scheme = $scheme
                        Command = $cmd
                    }) | Out-Null
                }
            } catch {}
        }
    }

    $log.Add("INFO: Checked $checkedHandlers URL protocol handlers.")
    if ($userWritableHandlers.Count -gt 0) {
        $log.Add("WARN: $($userWritableHandlers.Count) protocol handler(s) launch from user-writable paths.")
        foreach ($item in ($userWritableHandlers | Sort-Object Scheme -Unique | Select-Object -First 8)) {
            $log.Add("  - $($item.Scheme) -> $(Shorten-DisplayPath $item.Command)")
        }
        if ($userWritableHandlers.Count -gt 8) {
            $log.Add("  - ... plus $($userWritableHandlers.Count - 8) more")
        }
    } else {
        $log.Add("PASS: No unexpected user-writable URL protocol handlers.")
    }

    if ($suspiciousHandlers.Count -gt 0) {
        $log.Add("FAIL: $($suspiciousHandlers.Count) suspicious URL protocol handler(s) detected.")
        foreach ($item in ($suspiciousHandlers | Sort-Object Scheme -Unique | Select-Object -First 8)) {
            $log.Add("  - $($item.Scheme) -> $(Shorten-DisplayPath $item.Command)")
        }
        if ($suspiciousHandlers.Count -gt 8) {
            $log.Add("  - ... plus $($suspiciousHandlers.Count - 8) more")
        }
    } else {
        $log.Add("PASS: No suspicious URL protocol handlers detected.")
    }
} catch { $log.Add("INFO: URL protocol scan skipped.") }

# Prefetch tamper / disabled checks
try {
    $prefetchPath = Join-Path $env:SystemRoot "Prefetch"
    if (-not (Test-Path $prefetchPath)) {
        $log.Add("FAIL: Prefetch folder is missing."); $flags++
    } else {
        $pfCount = @(Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue).Count
        if ($pfCount -eq 0) {
            $log.Add("WARN: Prefetch folder contains no .pf files.")
        }
    }

    $pfReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    if (Test-Path $pfReg) {
        $enablePrefetcher = (Get-ItemProperty $pfReg -Name EnablePrefetcher -ErrorAction SilentlyContinue).EnablePrefetcher
        if ($null -ne $enablePrefetcher -and $enablePrefetcher -eq 0) {
            $log.Add("FAIL: EnablePrefetcher is disabled."); $flags++
        }
    }

    $sysMain = Get-Service -Name "SysMain" -ErrorAction SilentlyContinue
    if ($sysMain -and $sysMain.StartType -eq "Disabled") {
        $log.Add("WARN: SysMain service is disabled.")
    }
} catch { $log.Add("INFO: Prefetch integrity checks skipped.") }

# Explorer restart heuristic
try {
    $osInfo = (Get-CachedCimInstance "Win32_OperatingSystem" | Select-Object -First 1)
    $explorerProc = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
    if ($osInfo -and $explorerProc) {
        $systemUptimeMinutes   = [math]::Round(((Get-Date) - $osInfo.LastBootUpTime).TotalMinutes, 2)
        $explorerUptimeMinutes = [math]::Round(((Get-Date) - $explorerProc.StartTime).TotalMinutes, 2)
        if ($systemUptimeMinutes -gt 60 -and $explorerUptimeMinutes -lt 10) {
            $log.Add("WARN: Explorer appears to have restarted recently ($explorerUptimeMinutes min) while system uptime is $systemUptimeMinutes min.")
        }
    }
} catch { $log.Add("INFO: Explorer uptime heuristic skipped.") }

# Hidden/invisible character filename heuristic, but only when blacklist terms are also implicated
try {
    $candidateRoots = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads",
        "$env:APPDATA",
        "$env:LOCALAPPDATA"
    ) | Where-Object { $_ -and (Test-Path $_) }

    $hiddenCharHits = New-Object System.Collections.Generic.List[string]
    foreach ($root in $candidateRoots) {
        foreach ($f in (Get-ChildItem $root -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '\.(exe|dll|sys|bat|cmd|ps1|vbs|js|jar|lnk)$' })) {
            $candidateText = "$($f.Name) $($f.FullName)"
            if (Test-HiddenOrUnicodeName $f.Name -and (Test-BlacklistTerm $candidateText)) {
                $hiddenCharHits.Add($f.FullName) | Out-Null
                $flags++
            }
        }
    }
    if ($hiddenCharHits.Count -gt 0) {
        $uniqueHidden = $hiddenCharHits | Sort-Object -Unique
        $log.Add("FAIL: $($uniqueHidden.Count) hidden-character blacklisted file name(s) detected.")
        foreach ($path in ($uniqueHidden | Select-Object -First 8)) {
            $cleanName = ([regex]::Replace((Split-Path $path -Leaf), '[\x00-\x1F\x7F\u200B-\u200F\u202A-\u202E\u2060\uFEFF]', ''))
            $log.Add("  - $(Shorten-DisplayPath $path) [displayed as: $cleanName]")
        }
        if ($uniqueHidden.Count -gt 8) {
            $log.Add("  - ... plus $($uniqueHidden.Count - 8) more")
        }
    } else {
        $log.Add("PASS: No hidden-character blacklisted file names detected.")
    }
} catch { $log.Add("INFO: Hidden-character filename scan skipped.") }

# Expanded PowerShell history review for bypass / cleaner / artifact tamper commands
try {
    $psHistPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistPath) {
        $historyRegex = [regex]::new('(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath|ExclusionProcess|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|wevtutil\s+cl|Clear-EventLog|fsutil\s+usn\s+deletejournal|vssadmin\s+delete\s+shadows|bcdedit\b.*hypervisorlaunchtype|reg\s+delete\b.*PrefetchParameters)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($line in (Get-Content $psHistPath -ErrorAction SilentlyContinue)) {
            if ($historyRegex.IsMatch($line)) {
                $log.Add("FAIL: Suspicious PowerShell/CLI history command -> $line")
                $flags++
            }
        }
    }
} catch { $log.Add("INFO: Extended PowerShell history review skipped.") }



# ==============================================================================
#   SECTION: HIGH-SIGNAL TELEMETRY CORRELATION
# ==============================================================================
$log.Add("`n[SECTION: HIGH-SIGNAL TELEMETRY CORRELATION]")
try {
    if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) {
        $now = Get-Date
        $windowStart = $now.AddDays(-7)
        $sysmonFailCount = 0
        $sysmonWarnCount = 0

        # Event ID 8 - CreateRemoteThread into protected targets
        foreach ($evt in (Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=8; StartTime=$windowStart } -ErrorAction SilentlyContinue)) {
            $src = Get-EventMessageField -Message $evt.Message -Name 'SourceImage'
            $tgt = Get-EventMessageField -Message $evt.Message -Name 'TargetImage'
            if (Test-ProtectedTarget $tgt) {
                $log.Add("FAIL: Sysmon EID 8 remote thread into protected target -> Source: $src | Target: $tgt | Time: $($evt.TimeCreated)")
                $flags++; $sysmonFailCount++
            }
        }

        # Event ID 7 - suspicious image loads into protected targets
        foreach ($evt in (Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=7; StartTime=$windowStart } -ErrorAction SilentlyContinue | Select-Object -First 4000)) {
            $proc = Get-EventMessageField -Message $evt.Message -Name 'Image'
            $img  = Get-EventMessageField -Message $evt.Message -Name 'ImageLoaded'
            if (-not (Test-ProtectedTarget $proc)) { continue }
            if ([string]::IsNullOrWhiteSpace($img)) { continue }
            $sigInfo = Get-FileSignatureInfo -Path $img
            if ((Test-UserWritablePath $img) -and (-not $sigInfo.Allowed)) {
                $log.Add("FAIL: Sysmon EID 7 suspicious module in protected target -> Proc: $proc | Module: $img | Sig: $($sigInfo.Status) | Signer: $($sigInfo.Signer)")
                $flags++; $sysmonFailCount++
            }
        }

        # Event ID 10 - suspicious process access into protected targets
        foreach ($evt in (Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=10; StartTime=$windowStart } -ErrorAction SilentlyContinue | Select-Object -First 3000)) {
            $src = Get-EventMessageField -Message $evt.Message -Name 'SourceImage'
            $tgt = Get-EventMessageField -Message $evt.Message -Name 'TargetImage'
            if (-not (Test-ProtectedTarget $tgt)) { continue }
            $srcSig = Get-FileSignatureInfo -Path $src
            if ((Test-UserWritablePath $src) -or (-not $srcSig.Allowed) -or (Test-SuspiciousIndicator $src -BlacklistOnly)) {
                $log.Add("WARN: Sysmon EID 10 suspicious process access into protected target -> Source: $src | Target: $tgt | Sig: $($srcSig.Status)")
                $flags++; $sysmonWarnCount++
            }
        }

        # Event ID 6 - driver loads
        foreach ($evt in (Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=6; StartTime=$windowStart } -ErrorAction SilentlyContinue | Select-Object -First 1500)) {
            $drv = Get-EventMessageField -Message $evt.Message -Name 'ImageLoaded'
            if ([string]::IsNullOrWhiteSpace($drv)) { continue }
            $sigInfo = Get-FileSignatureInfo -Path $drv
            if ((-not $sigInfo.Allowed) -and ((Test-UserWritablePath $drv) -or $sigInfo.Status -ne 'Valid')) {
                $log.Add("FAIL: Sysmon EID 6 suspicious driver load -> Driver: $drv | Sig: $($sigInfo.Status) | Signer: $($sigInfo.Signer)")
                $flags++; $sysmonFailCount++
            }
        }

        if ($sysmonFailCount -eq 0 -and $sysmonWarnCount -eq 0) {
            $log.Add('PASS: No high-signal Sysmon injection or driver telemetry matched the protected-target rules.')
        }
    } else {
        $log.Add('INFO: Sysmon operational log not present — high-signal telemetry checks downgraded to artifact-only.')
    }
} catch { $log.Add("INFO: High-signal telemetry correlation skipped — $($_.Exception.Message)") }

# ==============================================================================
#   SECTION: HIGH-SIGNAL PERSISTENCE & TAMPER CHECKS
# ==============================================================================
$log.Add("`n[SECTION: HIGH-SIGNAL PERSISTENCE & TAMPER CHECKS]")
try {
    $persistenceHits = 0

    foreach ($rk in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        try {
            $item = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($prop in $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
                $val = [string]$prop.Value
                if ((Test-UserWritablePath $val) -or $val -match 'powershell(\.exe)?\s+.*(-enc|-encodedcommand)' -or (Test-SuspiciousIndicator $val -BlacklistOnly)) {
                    $log.Add("FAIL: Suspicious Run key persistence -> $rk | $($prop.Name) | $val")
                    $flags++; $persistenceHits++
                }
            }
        } catch {}
    }

    try {
        foreach ($task in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            foreach ($act in @($task.Actions)) {
                if ($null -eq $act) { continue }
                $cmd = (([string]$act.Execute) + ' ' + ([string]$act.Arguments)).Trim()
                if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
                if ((Test-UserWritablePath $cmd) -or $cmd -match 'powershell(\.exe)?\s+.*(-enc|-encodedcommand)' -or (Test-SuspiciousIndicator $cmd -BlacklistOnly)) {
                    $log.Add("FAIL: Suspicious scheduled task action -> $($task.TaskName) | $cmd")
                    $flags++; $persistenceHits++
                }
            }
        }
    } catch { $log.Add('INFO: Scheduled task deep scan skipped.') }

    try {
        foreach ($consumer in (Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue)) {
            $cmd = [string]$consumer.CommandLineTemplate
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
            if ((Test-UserWritablePath $cmd) -or (Test-SuspiciousIndicator $cmd -BlacklistOnly) -or $cmd -match 'powershell(\.exe)?\s+.*(-enc|-encodedcommand)') {
                $log.Add("FAIL: Suspicious WMI permanent consumer -> $($consumer.Name) | $cmd")
                $flags++; $persistenceHits++
            } else {
                $log.Add("WARN: WMI permanent consumer present -> $($consumer.Name) | $cmd")
            }
        }
    } catch { $log.Add('INFO: WMI permanent consumer scan skipped.') }

    try {
        $appInitKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        if (Test-Path $appInitKey) {
            $appInit = Get-ItemProperty -Path $appInitKey -ErrorAction SilentlyContinue
            if ($appInit -and $appInit.LoadAppInit_DLLs -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$appInit.AppInit_DLLs)) {
                $log.Add("FAIL: AppInit_DLLs configured -> $([string]$appInit.AppInit_DLLs)")
                $flags++; $persistenceHits++
            }
        }
    } catch { $log.Add('INFO: AppInit_DLLs check skipped.') }

    if ($persistenceHits -eq 0) {
        $log.Add('PASS: No high-signal persistence mechanisms matched the stricter rules.')
    }
} catch { $log.Add("INFO: High-signal persistence checks skipped — $($_.Exception.Message)") }

# ==============================================================================
#   SECTION: EVENT LOG / POWERSHELL PROFILE TAMPER
# ==============================================================================
$log.Add("`n[SECTION: EVENT LOG / POWERSHELL PROFILE TAMPER]")
try {
    $tamperHits = 0
    foreach ($evt in (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102; StartTime=(Get-Date).AddDays(-14) } -MaxEvents 10 -ErrorAction SilentlyContinue)) {
        $log.Add("FAIL: Security event log cleared (Event ID 1102) -> $($evt.TimeCreated)")
        $flags++; $tamperHits++
    }

    $profilePaths = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost) | Where-Object { $_ }
    foreach ($profilePath in $profilePaths) {
        try {
            if (-not (Test-Path $profilePath)) { continue }
            $content = Get-Content -Path $profilePath -Raw -ErrorAction SilentlyContinue
            if ($content -match 'Add-MpPreference|Set-MpPreference|FromBase64String|EncodedCommand|wevtutil\s+cl|fsutil\s+usn\s+deletejournal') {
                $log.Add("FAIL: Suspicious PowerShell profile content -> $profilePath")
                $flags++; $tamperHits++
            }
        } catch {}
    }

    if ($tamperHits -eq 0) { $log.Add('PASS: No cleared security-log events or suspicious PowerShell profiles detected.') }
} catch { $log.Add("INFO: Event log / PowerShell profile tamper checks skipped — $($_.Exception.Message)") }

Update-ScanProgress -Percent 100
$log.Add("Scan Completed: $(Get-Date)")

$finalLog = Compress-LogLines -Lines $log
$finalLog | Out-File -FilePath $logPath -Encoding UTF8

Show-PAHWindow

$webhookResult, $webhookMsg = Send-AuditWebhook `
    -Url         $webhookUrl `
    -LogFilePath $logPath `
    -FlagCount   $flags `
    -MachineName $env:COMPUTERNAME `
    -UserName    $env:USERNAME

if ($webhookResult) {
    Write-Host "✅ Webhook sent." -ForegroundColor Green
} else {
    Write-Host "❌ Webhook dispatch failed: $webhookMsg" -ForegroundColor Red
}

Write-Host ""
$scanComplete = @"

███████╗ ██████╗ █████╗ ███╗   ██╗     ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗     ███████╗████████╗███████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║     ██╔════╝╚══██╔══╝██╔════╝
███████╗██║     ███████║██╔██╗ ██║    ██║     ██║   ██║██╔████╔██║██████╔╝██║     █████╗     ██║   █████╗  
╚════██║██║     ██╔══██║██║╚██╗██║    ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝     ██║   ██╔══╝  
███████║╚██████╗██║  ██║██║ ╚████║    ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗███████╗   ██║   ███████╗
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝     ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚══════╝
"@
Write-Host $scanComplete -ForegroundColor Green
Write-Host "`n                  Please proceed with your game.`n" -ForegroundColor Green

$madeBy = @"

███╗   ███╗ █████╗ ██████╗ ███████╗    ██████╗ ██╗   ██╗    ███████╗██╗   ██╗██████╗ ███████╗██╗   ██╗███████╗██╗   ██╗
████╗ ████║██╔══██╗██╔══██╗██╔════╝    ██╔══██╗╚██╗ ██╔╝    ██╔════╝██║   ██║██╔══██╗╚══███╔╝╚██╗ ██╔╝╚══███╔╝╚██╗ ██╔╝
██╔████╔██║███████║██║  ██║█████╗      ██████╔╝ ╚████╔╝     ███████╗██║   ██║██████╔╝  ███╔╝  ╚████╔╝   ███╔╝  ╚████╔╝ 
██║╚██╔╝██║██╔══██║██║  ██║██╔══╝      ██╔══██╗  ╚██╔╝      ╚════██║██║   ██║██╔══██╗ ███╔╝    ╚██╔╝   ███╔╝    ╚██╔╝  
██║ ╚═╝ ██║██║  ██║██████╔╝███████╗    ██████╔╝   ██║       ███████║╚██████╔╝██████╔╝███████╗   ██║   ███████╗   ██║   
╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝    ╚═════╝    ╚═╝       ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   

PAH (Process Activity History) should appear near the end of the scan.
"@
Write-Host $madeBy -ForegroundColor Red
Write-Host "                                         - Sub's Recording Policy " -ForegroundColor White
Write-Host "`n"

