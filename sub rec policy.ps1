# ==============================================================================
#   SUBS REC POLICY
# ==============================================================================


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$webhookUrl = "https://discord.com/api/webhooks/1492882358125199371/zaFJcZ94jZCXTaDehvGfa8elwZtJOLSdUtGtWzjpH3FqBABWaYuao_O9H4uzS3c9_mQp"
$logPath = "$env:TEMP\Subrecresult.txt"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "CRITICAL ERROR: Administrator privileges required." -ForegroundColor Red; Pause; exit 1
}

Clear-Host
Write-Host "=== Sub Rec Policy  ===" -ForegroundColor Cyan
Write-Host "Scan In Progress... This may take some minutes." -ForegroundColor White

$log = New-Object System.Collections.Generic.List[string]
$log.Add("======================================================")
$log.Add("        Sub Rec Policy: $(Get-Date)            ")
$log.Add("======================================================")

# ======================================================
# EXTENDED INTEGRITY + ENVIRONMENT AUDIT
# PLACE AFTER SYSTEM CONFIG VALIDATION
# ======================================================


# --- CRITICAL REGISTRY INTEGRITY ---
$log.Add("`n[SECTION: CRITICAL REGISTRY INTEGRITY]")

function Check-RegistryClean {
    param (
        [string]$Path,
        [string]$Name,
        [switch]$StrictDefaultOnly
    )

    if (Test-Path $Path) {
        try {
            $item = Get-Item $Path
            $values = $item.GetValueNames()

            if ($StrictDefaultOnly) {
                if ($values.Count -le 1 -and ($values -contains "" -or $values.Count -eq 0)) {
                    $log.Add("PASS: $Name is clean (Default only)")
                } else {
                    foreach ($v in $values) {
                        if ($v -ne "") {
                            $log.Add("FAIL: $Name has extra value -> $v")
                            $flags++
                        }
                    }
                }
            } else {
                foreach ($v in $values) {
                    if ($v -ne "") {
                        $log.Add("INFO: $Name contains value -> $v")
                    }
                }
            }
        } catch {
            $log.Add("WARNING: Could not access $Name")
        }
    } else {
        $log.Add("INFO: $Name not found")
    }
}

# --- Registry Paths ---
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" "Windows Config Key"
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" "IFEO (Debugger Injection Risk)"
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction" "Defender Threat Actions" -StrictDefaultOnly
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" "Defender Exclusions (Extensions)" -StrictDefaultOnly



# --- TASKBAR & SYSTEM TRAY ANALYSIS ---
$log.Add("`n[SECTION: TASKBAR & SYSTEM TRAY ANALYSIS]")

# Visible taskbar apps (windows with titles)
try {
    $explorerProcs = Get-Process | Where-Object { $_.MainWindowTitle -ne "" }

    foreach ($p in $explorerProcs) {
        $log.Add("TASKBAR: $($p.ProcessName) | Window: $($p.MainWindowTitle)")
    }
} catch {
    $log.Add("INFO: Could not enumerate taskbar windows")
}

# Startup (common tray apps)
try {
    $startupPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike "PS*") {
                    $log.Add("TRAY/STARTUP: $($_.Name) -> $($_.Value)")
                }
            }
        }
    }
} catch {
    $log.Add("INFO: Could not enumerate startup items")
}

# Tray cache (hidden icons indicator)
try {
    $trayKey = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify"

    if (Test-Path $trayKey) {
        $log.Add("INFO: Tray cache present (hidden tray icons likely exist)")
    }
} catch {
    $log.Add("INFO: Could not access tray cache")
}

# Background processes (likely tray apps)
$backgroundProcs = Get-Process | Where-Object {
    $_.MainWindowHandle -eq 0 -and $_.ProcessName -notmatch "svchost|System|Idle"
}

foreach ($bp in $backgroundProcs) {
    $log.Add("BACKGROUND: $($bp.ProcessName)")
}


# --- SYSTEM CONFIG VALIDATION ---
$log.Add("`n[SECTION: SYSTEM CONFIG VALIDATION]")

$issues = $false

# --- 1. Mouse Pointer Scheme (main.cpl) ---
try {
    $cursorKey = "HKCU:\Control Panel\Cursors"
    $scheme = (Get-ItemProperty -Path $cursorKey -Name Scheme -ErrorAction SilentlyContinue).Scheme

    if ($scheme -eq $null -or $scheme -eq "" -or $scheme -eq "Windows Default (system scheme)") {
        $log.Add("PASS: Mouse pointer scheme is default")
    } else {
        $log.Add("FAIL: Mouse pointer scheme is modified ($scheme)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify mouse pointer scheme")
}

# --- 2. Performance Settings (visual effects) ---
try {
    $perfKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $visualFX = (Get-ItemProperty -Path $perfKey -Name VisualFXSetting -ErrorAction SilentlyContinue).VisualFXSetting

    # 3 = Let Windows choose / often means not fully enabled
    # 2 = Adjust for best appearance (what you want)
    if ($visualFX -eq 2) {
        $log.Add("PASS: Visual effects fully enabled")
    } else {
        $log.Add("FAIL: Visual effects not fully enabled (Value: $visualFX)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify performance settings")
}

# --- SYSTEM CONFIG VALIDATION ---
$log.Add("`n[SECTION: SYSTEM CONFIG VALIDATION]")

$issues = $false

# --- 1. Mouse Pointer Scheme ---
try {
    $cursorKey = "HKCU:\Control Panel\Cursors"
    $scheme = (Get-ItemProperty -Path $cursorKey -Name Scheme -ErrorAction SilentlyContinue).Scheme

    if ([string]::IsNullOrWhiteSpace($scheme) -or $scheme -like "*Windows Default*") {
        $log.Add("PASS: Mouse pointer scheme is default ($scheme)")
    } else {
        $log.Add("FAIL: Mouse pointer scheme is modified ($scheme)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify mouse pointer scheme")
}

# --- 2. Visual Effects ---
try {
    $perfKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $visualFX = (Get-ItemProperty -Path $perfKey -Name VisualFXSetting -ErrorAction SilentlyContinue).VisualFXSetting

    # 1 = Best appearance (all visuals enabled)
    if ($visualFX -eq 1) {
        $log.Add("PASS: Visual effects fully enabled (Value: $visualFX)")
    } else {
        $log.Add("FAIL: Visual effects not fully enabled (Value: $visualFX)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify performance settings")
}

# --- 3. UAC Level ---
try {
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    $consent = (Get-ItemProperty -Path $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $promptSecure = (Get-ItemProperty -Path $uacKey -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    $enableLua = (Get-ItemProperty -Path $uacKey -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA

    # Second lowest = prompt without secure desktop
    if ($enableLua -eq 1 -and $consent -eq 5 -and $promptSecure -eq 0) {
        $log.Add("PASS: UAC is set to second lowest (Consent: $consent, SecureDesktop: $promptSecure)")
    } else {
        $log.Add("FAIL: UAC not at expected level (Consent: $consent, SecureDesktop: $promptSecure, EnableLUA: $enableLua)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify UAC settings")
}

# --- ENFORCEMENT ---
if ($issues) {
    $log.Add("FAIL: System configuration requirements not met")

    Write-Host "`n[!] You must fix the following before continuing:" -ForegroundColor Red
    Write-Host "- Reset mouse pointers to Windows Default" -ForegroundColor Yellow
    Write-Host "- Enable all visual effects (Best Appearance)" -ForegroundColor Yellow
    Write-Host "- Set UAC to 'Notify me only when apps try to make changes (no dim)'" -ForegroundColor Yellow
    Write-Host "`nThen rerun the audit." -ForegroundColor Cyan

    Pause
    exit 1
} else {
    $log.Add("PASS: All system configuration checks passed")
}


# --- 1. HARDWARE & DISPLAY ---
$log.Add("`n[SECTION 1: HARDWARE]")
$displays = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams | Where-Object { $_.Active }
$displayCount = ($displays | Measure-Object).Count
$log.Add("STATUS: Active Displays: $displayCount $(if($displayCount -eq 1){"(PASS)"}else{"(FAIL)"})")

# --- 2. MASTER BLACKLIST (Roblox/Cheats) ---
# "config" has been removed.
$cheatBlacklist = @(
    "matcha", "olduimatrix", "autoexe", "monkeyaim", "thunderaim", "thunderclient", "celex", "matrix", 
    "triggerbot", "solara", "xeno", "wave", "cloudy", "tupical", "horizon", "myst", "celery", "zarora", 
    "juju", "nezure", "FusionHacks", "aimmy", "Fluxus", "clumsy", "MystW", "isabelle", "dx9ware", 
    "injector", "cheat", "hack", "esp", "aimbot", "exploit", "executor", "softaim", "d3d9.dll",
    "pcileech", "kdmapper", "vape", "phantom", "killaura", "usermode", "internal", 
    "external", "bypass", "loader", "spoofer", "hwid", "silent", "fov", "recoil", "nospread",
    "synapse", "krnl", "sentinel", "sirhurt", "skisploit", "comet", "oxygen u", "electron", "nihon", 
    "evon", "vega x", "delta", "arceus", "hydrogen", "codex", "valyse", "fluctus", "incognito",
    "scriptware", "sw-m", "ro-exec", "krampus", "macsploit"
)

# --- 3. FILESYSTEM FORENSICS (Prefetch & KeyAuth) ---
$log.Add("`n[SECTION 2: FILESYSTEM FORENSICS]")

# Prefetch Scan (FULL VISIBILITY MODE)
try {
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue

    if ($pfFiles) {
        $log.Add("--- Prefetch Scan (Full Execution History) ---")
        $log.Add("INFO: Total Prefetch Files: $($pfFiles.Count)")

        foreach ($pf in $pfFiles | Sort-Object LastWriteTime -Descending) {

            # Extract executable name (cleaner output)
            $exeName = ($pf.BaseName -split "-")[0]

            $log.Add("PREFETCH: $exeName | Last Run: $($pf.LastWriteTime)")
            
            # Optional: still flag suspicious names
            foreach ($w in $cheatBlacklist) {
                if ($exeName -ilike "*$w*") {
                    $log.Add("⚠️ FLAGGED: Suspicious Prefetch Entry -> $exeName")
                    $flags++
                    break
                }
            }
        }

        $log.Add("INFO: Prefetch scan completed successfully.")
    } else {
        $log.Add("WARNING: Prefetch directory empty or inaccessible.")
    }

} catch {
    $log.Add("FAIL: Prefetch access denied or scan error.")
}

# KeyAuth Check
try {
    if (Test-Path "C:\ProgramData\KeyAuth\debug") {
        $folders = Get-ChildItem "C:\ProgramData\KeyAuth\debug" -Directory
        foreach ($f in $folders) { $log.Add("FAIL: KeyAuth/Cheat Folder Detected: $($f.FullName)") }
    } else { $log.Add("PASS: No KeyAuth debug folders found.") }
} catch { $log.Add("INFO: KeyAuth path clean.") }

# --- 4. ROBLOX BOOTSTRAPPER AUDIT ---
$log.Add("`n[SECTION 3: ROBLOX BOOTSTRAPPER AUDIT]")

$bootstrapPaths = @(
    @{ Name = "Bloxstrap"; Path = "$env:LOCALAPPDATA\Bloxstrap\Settings.json" },
    @{ Name = "Fishstrap"; Path = "$env:LOCALAPPDATA\Fishstrap" },
    @{ Name = "Voidstrap"; Path = "$env:LOCALAPPDATA\Voidstrap" },
    @{ Name = "Plexity"; Path = "$env:LOCALAPPDATA\Plexity" }
)

$bootstrapDetected = $false

foreach ($b in $bootstrapPaths) {
    if (Test-Path $b.Path) {
        $bootstrapDetected = $true
        $log.Add("INFO: Detected Bootstrapper -> $($b.Name)")

        # Specific handling for Bloxstrap config
        if ($b.Name -eq "Bloxstrap" -and $b.Path -like "*.json") {
            try {
                $settings = Get-Content $b.Path -Raw | ConvertFrom-Json
                if ($null -eq $settings.CustomIntegrations -or $settings.CustomIntegrations.Count -eq 0) {
                    $log.Add("PASS: Bloxstrap Custom Integrations EMPTY")
                } else {
                    foreach ($ci in $settings.CustomIntegrations) {
                        $log.Add("FAIL: Bloxstrap Integration: $($ci.Name) -> $($ci.Location)")
                    }
                }
            } catch {
                $log.Add("WARNING: Bloxstrap config unreadable")
            }
        }
        else {
            # Generic handling for alternatives
            try {
                $files = Get-ChildItem $b.Path -Recurse -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    foreach ($w in $cheatBlacklist) {
                        if ($f.Name -ilike "*$w*") {
                            $log.Add("FAIL: Suspicious file in $($b.Name): $($f.FullName)")
                            $flags++
                        }
                    }
                }
            } catch {
                $log.Add("INFO: Could not fully scan $($b.Name)")
            }
        }
    }
}

if (-not $bootstrapDetected) {
    $log.Add("PASS: No known Roblox bootstrappers detected.")
}

# --- DEFENDER FULL SECURITY AUDIT ---
$log.Add("`n[SECTION 4: DEFENDER FULL SECURITY AUDIT]")

# Ensure flags exists
if (-not $flags) { $flags = 0 }

# -----------------------------
# 1. defender
# -----------------------------
try {
    $mp = Get-MpComputerStatus
    $pref = Get-MpPreference

    # Real-time protection
    if ($mp.RealTimeProtectionEnabled) {
        $log.Add("PASS: Real-time protection ON")
    } else {
        $log.Add("FAIL: Real-time protection OFF")
        $flags++
    }

    # Behavior monitoring
    if ($mp.BehaviorMonitorEnabled) {
        $log.Add("PASS: Behavior monitoring ON")
    } else {
        $log.Add("FAIL: Behavior monitoring OFF")
        $flags++
    }

    # IOAV (downloads scanning)
    if ($mp.IOAVProtectionEnabled) {
        $log.Add("PASS: IOAV protection ON")
    } else {
        $log.Add("FAIL: IOAV protection OFF")
        $flags++
    }

    # Cloud protection
    if (-not $pref.DisableBlockAtFirstSeen) {
        $log.Add("PASS: Cloud protection ON")
    } else {
        $log.Add("FAIL: Cloud protection OFF")
        $flags++
    }

} catch {
    $log.Add("FAIL: Could not read Defender status")
    $flags++
}

# -----------------------------
# 2. EXCLUSIONS 
# -----------------------------
try {
    if ($pref.ExclusionPath -or $pref.ExclusionProcess -or $pref.ExclusionExtension) {
        $log.Add("FAIL: Defender exclusions detected")

        foreach ($e in $pref.ExclusionPath) {
            $log.Add("EXCLUSION PATH: $e")
        }
        foreach ($e in $pref.ExclusionProcess) {
            $log.Add("EXCLUSION PROCESS: $e")
        }
        foreach ($e in $pref.ExclusionExtension) {
            $log.Add("EXCLUSION EXT: $e")
        }

        $flags++
    } else {
        $log.Add("PASS: No Defender exclusions")
    }
} catch {
    $log.Add("INFO: Could not read exclusions")
}

# -----------------------------
# 3. ALLOWED THREATS
# -----------------------------
try {
    if ($pref.ThreatIDDefaultAction_Ids) {
        $log.Add("FAIL: Allowed threats detected in Defender")
        $flags++
    } else {
        $log.Add("PASS: No allowed threats")
    }
} catch {
    $log.Add("INFO: Could not check allowed threats")
}

# -----------------------------
# 4. Regedit check
# -----------------------------
function Scan-RegistryTree {
    param ($BasePath, $Label)

    if (Test-Path $BasePath) {
        # Include root key + all children
        $allKeys = @()
        $allKeys += Get-Item $BasePath
        $allKeys += Get-ChildItem -Path $BasePath -Recurse -ErrorAction SilentlyContinue

        foreach ($key in $allKeys) {
            try {
                $values = $key.GetValueNames()

                foreach ($v in $values) {
                    if ($v -ne "") {
                        $log.Add("FAIL: $Label -> Value '$v' in $($key.Name)")
                        $flags++
                    }
                }

                $subkeys = Get-ChildItem $key.PSPath -ErrorAction SilentlyContinue
                foreach ($sk in $subkeys) {
                    $log.Add("FAIL: $Label -> Subkey exists: $($sk.PSChildName)")
                    $flags++
                }

            } catch {}
        }
    } else {
        $log.Add("PASS: $Label not present")
    }
}

Scan-RegistryTree "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction" "Threat Actions"
Scan-RegistryTree "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" "Exclusion Extensions"

# -----------------------------
# 5. NOTIFICATIONS CHECK (FIXED)
# -----------------------------
try {
    $notifKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"

    if (Test-Path $notifKey) {
        $subKeys = Get-ChildItem -Path $notifKey -ErrorAction SilentlyContinue

        $disabledFound = $false

        foreach ($sk in $subKeys) {
            try {
                $props = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue

                foreach ($p in $props.PSObject.Properties) {
                    if ($p.MemberType -eq "NoteProperty") {
                        if ($p.Value -eq 0) {
                            $log.Add("FAIL: Notifications disabled for $($sk.PSChildName) -> $($p.Name)")
                            $flags++
                            $disabledFound = $true
                        }
                    }
                }

            } catch {}
        }

        if (-not $disabledFound) {
            $log.Add("PASS: Notifications appear enabled")
        }

    } else {
        $log.Add("INFO: Notification settings not found")
    }

} catch {
    $log.Add("INFO: Could not verify notifications")
}
# --- 6. DEEP REGISTRY ENGINE (Exhaustive Scan) ---
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
    "HKCR:\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\Microsoft\Tracing",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
)

$flags = 0
foreach ($p in $regPaths) {
    if (Test-Path $p) {
        try {
            $item = Get-Item -Path $p -ErrorAction SilentlyContinue
            foreach ($name in $item.GetValueNames()) {
                foreach ($w in $cheatBlacklist) {
                    if ($name -ilike "*$w*") { 
                        $log.Add("FAIL: Registry Match [$w] in $p -> Name: $name")
                        $flags++
                    }
                }
            }
            $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            $props.PSObject.Properties | ForEach-Object {
                $val = $_.Value.ToString()
                foreach ($w in $cheatBlacklist) {
                    if ($val -ilike "*$w*") { 
                        $log.Add("FAIL: Registry Value Match [$w] in $p -> Value: $val")
                        $flags++
                    }
                }
            }
        } catch {}
    }
}

# --- 7. LIVE PROCESS AUDIT  ---
$log.Add("`n[SECTION 6: ACTIVE PROCESSES]")
$macroDetect = @("autohotkey", "ahk", "macro", "synapse", "logitech", "itask", "x-mouse", "tinytask", "autoclicker", "jitbit")
$recordDetect = @("obs64", "obs32", "streamlabs", "medal", "shadowplay", "nvcontainer", "NVIDIA Share", "bandicam", "fraps")

$procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
foreach ($proc in $procs) {
    $desc = ""; try { $desc = $proc.MainModule.FileVersionInfo.FileDescription } catch {}

    # Cheats (Failure)
    foreach ($c in $cheatBlacklist) {
        if ($proc.ProcessName -ilike "*$c*" -or $desc -ilike "*$c*") {
            $log.Add("FAIL: Active Cheat Process: $($proc.ProcessName) ($desc)")
            $flags++
        }
    }
    # Macros (Detection)
    foreach ($m in $macroDetect) {
        if ($proc.ProcessName -ilike "*$m*" -or $desc -ilike "*$m*") { $log.Add("INFO: Macro/Input Process: $($proc.ProcessName)") }
    }
    # Recording (Detection)
    foreach ($r in $recordDetect) {
        if ($proc.ProcessName -ilike "*$r*") {
            $rec = "IDLE"; try { if (($proc.Modules.ModuleName -match "nvenc|nvapi|obs|vce") -and ($proc.CPU -gt 0.01)) { $rec = "ACTIVE" } } catch {}
            $log.Add("INFO: Recorder Process [$($proc.ProcessName)] is $rec")
        }
    }
}
# --- DLL INJECTION HEURISTICS ---
$log.Add("`n[SECTION: DLL INJECTION HEURISTICS]")

foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
    try {
        $modules = $proc.Modules

        foreach ($m in $modules) {
            $path = $m.FileName.ToLower()

            # Suspicious locations
            if ($path -match "appdata|temp|roaming") {
                $log.Add("FAIL: Suspicious DLL in $($proc.ProcessName) -> $path")
                $flags++
            }

            # Known cheat keywords
            foreach ($w in $cheatBlacklist) {
                if ($path -like "*$w*") {
                    $log.Add("FAIL: Injected DLL match [$w] in $($proc.ProcessName)")
                    $flags++
                }
            }
        }
    } catch {}
}


# --- 8. PAH WINDOW (LIVE HISTORY) ---
Start-Job {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object Windows.Forms.Form
    $form.Text = "Process Active History (Live)"; $form.WindowState = 'Maximized'; $form.Topmost = $true
    $lb = New-Object Windows.Forms.ListBox; $lb.Dock = 'Fill'; $form.Controls.Add($lb)
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $timer = New-Object Windows.Forms.Timer; $timer.Interval = 2000
    $timer.Add_Tick({
        Get-Process | ForEach-Object {
            if (-not $seen.Contains($_.ProcessName)) {
                $seen.Add($_.ProcessName) | Out-Null
                $lb.Invoke([action]{ $lb.Items.Add("($(Get-Date -Format 'HH:mm:ss')) Launched: $($_.ProcessName)") })
            }
        }
    })
    $timer.Start(); [void]$form.ShowDialog()
} | Out-Null

# ======================================================
# REAL-TIME + MEMORY / HANDLE DETECTION (COMBINED)
# ======================================================

$log.Add("`n[SECTION: REAL-TIME + MEMORY DETECTION]")

$seen = @{}
$durationSeconds = 15   # how long to monitor (adjust if needed)
$endTime = (Get-Date).AddSeconds($durationSeconds)

while ((Get-Date) -lt $endTime) {

    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {

        $proc = $_
        $name = $proc.ProcessName.ToLower()

        # --- NEW PROCESS DETECTION ---
        if (-not $seen.ContainsKey($proc.Id)) {
            $seen[$proc.Id] = $true

            foreach ($w in $cheatBlacklist) {
                if ($name -like "*$w*") {
                    $log.Add("DETECTED: Live Process Match -> $name")
                    $flags++
                    break
                }
            }
        }

        # --- HANDLE COUNT CHECK ---
        try {
            if ($proc.HandleCount -gt 1000) {
                $log.Add("DETECTED: High Handle Count -> $name ($($proc.HandleCount))")
                $flags++
            }
        } catch {}

        # --- MEMORY USAGE CHECK ---
        try {
            if ($proc.WorkingSet -gt 500MB) {
                $log.Add("DETECTED: High Memory Usage -> $name")
                $flags++
            }
        } catch {}

    }

    Start-Sleep -Milliseconds 200
}

# --- 9. FINAL DISPATCH ---
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
                                                                                                                       
                                                                                                                       

DO NOT CLOSE "PAH (Process activity History)", if closed your recording will be Failed
"@
Write-Host $madeBy -ForegroundColor Red
Write-Host "                                         - Sub's Recording Policy" -ForegroundColor White
Write-Host "`n"

# ==============================================================================
#   SUBS REC POLICY
# ==============================================================================


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$webhookUrl = "https://discord.com/api/webhooks/1492882358125199371/zaFJcZ94jZCXTaDehvGfa8elwZtJOLSdUtGtWzjpH3FqBABWaYuao_O9H4uzS3c9_mQp"
$logPath = "$env:TEMP\Subrecresult.txt"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "CRITICAL ERROR: Administrator privileges required." -ForegroundColor Red; Pause; exit 1
}

Clear-Host
Write-Host "=== Sub Rec Policy  ===" -ForegroundColor Cyan
Write-Host "Scan In Progress... This may take some minutes." -ForegroundColor White

$log = New-Object System.Collections.Generic.List[string]
$log.Add("======================================================")
$log.Add("        Sub Rec Policy: $(Get-Date)            ")
$log.Add("======================================================")

# ======================================================
# EXTENDED INTEGRITY + ENVIRONMENT AUDIT
# PLACE AFTER SYSTEM CONFIG VALIDATION
# ======================================================


# --- CRITICAL REGISTRY INTEGRITY ---
$log.Add("`n[SECTION: CRITICAL REGISTRY INTEGRITY]")

function Check-RegistryClean {
    param (
        [string]$Path,
        [string]$Name,
        [switch]$StrictDefaultOnly
    )

    if (Test-Path $Path) {
        try {
            $item = Get-Item $Path
            $values = $item.GetValueNames()

            if ($StrictDefaultOnly) {
                if ($values.Count -le 1 -and ($values -contains "" -or $values.Count -eq 0)) {
                    $log.Add("PASS: $Name is clean (Default only)")
                } else {
                    foreach ($v in $values) {
                        if ($v -ne "") {
                            $log.Add("FAIL: $Name has extra value -> $v")
                            $flags++
                        }
                    }
                }
            } else {
                foreach ($v in $values) {
                    if ($v -ne "") {
                        $log.Add("INFO: $Name contains value -> $v")
                    }
                }
            }
        } catch {
            $log.Add("WARNING: Could not access $Name")
        }
    } else {
        $log.Add("INFO: $Name not found")
    }
}

# --- Registry Paths ---
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" "Windows Config Key"
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" "IFEO (Debugger Injection Risk)"
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction" "Defender Threat Actions" -StrictDefaultOnly
Check-RegistryClean "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" "Defender Exclusions (Extensions)" -StrictDefaultOnly



# --- TASKBAR & SYSTEM TRAY ANALYSIS ---
$log.Add("`n[SECTION: TASKBAR & SYSTEM TRAY ANALYSIS]")

# Visible taskbar apps (windows with titles)
try {
    $explorerProcs = Get-Process | Where-Object { $_.MainWindowTitle -ne "" }

    foreach ($p in $explorerProcs) {
        $log.Add("TASKBAR: $($p.ProcessName) | Window: $($p.MainWindowTitle)")
    }
} catch {
    $log.Add("INFO: Could not enumerate taskbar windows")
}

# Startup (common tray apps)
try {
    $startupPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike "PS*") {
                    $log.Add("TRAY/STARTUP: $($_.Name) -> $($_.Value)")
                }
            }
        }
    }
} catch {
    $log.Add("INFO: Could not enumerate startup items")
}

# Tray cache (hidden icons indicator)
try {
    $trayKey = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify"

    if (Test-Path $trayKey) {
        $log.Add("INFO: Tray cache present (hidden tray icons likely exist)")
    }
} catch {
    $log.Add("INFO: Could not access tray cache")
}

# Background processes (likely tray apps)
$backgroundProcs = Get-Process | Where-Object {
    $_.MainWindowHandle -eq 0 -and $_.ProcessName -notmatch "svchost|System|Idle"
}

foreach ($bp in $backgroundProcs) {
    $log.Add("BACKGROUND: $($bp.ProcessName)")
}


# --- SYSTEM CONFIG VALIDATION ---
$log.Add("`n[SECTION: SYSTEM CONFIG VALIDATION]")

$issues = $false

# --- 1. Mouse Pointer Scheme (main.cpl) ---
try {
    $cursorKey = "HKCU:\Control Panel\Cursors"
    $scheme = (Get-ItemProperty -Path $cursorKey -Name Scheme -ErrorAction SilentlyContinue).Scheme

    if ($scheme -eq $null -or $scheme -eq "" -or $scheme -eq "Windows Default (system scheme)") {
        $log.Add("PASS: Mouse pointer scheme is default")
    } else {
        $log.Add("FAIL: Mouse pointer scheme is modified ($scheme)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify mouse pointer scheme")
}

# --- 2. Performance Settings (visual effects) ---
try {
    $perfKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $visualFX = (Get-ItemProperty -Path $perfKey -Name VisualFXSetting -ErrorAction SilentlyContinue).VisualFXSetting

    # 3 = Let Windows choose / often means not fully enabled
    # 2 = Adjust for best appearance (what you want)
    if ($visualFX -eq 2) {
        $log.Add("PASS: Visual effects fully enabled")
    } else {
        $log.Add("FAIL: Visual effects not fully enabled (Value: $visualFX)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify performance settings")
}

# --- SYSTEM CONFIG VALIDATION ---
$log.Add("`n[SECTION: SYSTEM CONFIG VALIDATION]")

$issues = $false

# --- 1. Mouse Pointer Scheme ---
try {
    $cursorKey = "HKCU:\Control Panel\Cursors"
    $scheme = (Get-ItemProperty -Path $cursorKey -Name Scheme -ErrorAction SilentlyContinue).Scheme

    if ([string]::IsNullOrWhiteSpace($scheme) -or $scheme -like "*Windows Default*") {
        $log.Add("PASS: Mouse pointer scheme is default ($scheme)")
    } else {
        $log.Add("FAIL: Mouse pointer scheme is modified ($scheme)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify mouse pointer scheme")
}

# --- 2. Visual Effects ---
try {
    $perfKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $visualFX = (Get-ItemProperty -Path $perfKey -Name VisualFXSetting -ErrorAction SilentlyContinue).VisualFXSetting

    # 1 = Best appearance (all visuals enabled)
    if ($visualFX -eq 1) {
        $log.Add("PASS: Visual effects fully enabled (Value: $visualFX)")
    } else {
        $log.Add("FAIL: Visual effects not fully enabled (Value: $visualFX)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify performance settings")
}

# --- 3. UAC Level ---
try {
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    $consent = (Get-ItemProperty -Path $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $promptSecure = (Get-ItemProperty -Path $uacKey -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    $enableLua = (Get-ItemProperty -Path $uacKey -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA

    # Second lowest = prompt without secure desktop
    if ($enableLua -eq 1 -and $consent -eq 5 -and $promptSecure -eq 0) {
        $log.Add("PASS: UAC is set to second lowest (Consent: $consent, SecureDesktop: $promptSecure)")
    } else {
        $log.Add("FAIL: UAC not at expected level (Consent: $consent, SecureDesktop: $promptSecure, EnableLUA: $enableLua)")
        $issues = $true
    }
} catch {
    $log.Add("INFO: Could not verify UAC settings")
}

# --- ENFORCEMENT ---
if ($issues) {
    $log.Add("FAIL: System configuration requirements not met")

    Write-Host "`n[!] You must fix the following before continuing:" -ForegroundColor Red
    Write-Host "- Reset mouse pointers to Windows Default" -ForegroundColor Yellow
    Write-Host "- Enable all visual effects (Best Appearance)" -ForegroundColor Yellow
    Write-Host "- Set UAC to 'Notify me only when apps try to make changes (no dim)'" -ForegroundColor Yellow
    Write-Host "`nThen rerun the audit." -ForegroundColor Cyan

    Pause
    exit 1
} else {
    $log.Add("PASS: All system configuration checks passed")
}


# --- 1. HARDWARE & DISPLAY ---
$log.Add("`n[SECTION 1: HARDWARE]")
$displays = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams | Where-Object { $_.Active }
$displayCount = ($displays | Measure-Object).Count
$log.Add("STATUS: Active Displays: $displayCount $(if($displayCount -eq 1){"(PASS)"}else{"(FAIL)"})")

# --- 2. MASTER BLACKLIST (Roblox/Cheats) ---
# "config" has been removed.
$cheatBlacklist = @(
    "matcha", "olduimatrix", "autoexe", "monkeyaim", "thunderaim", "thunderclient", "celex", "matrix", 
    "triggerbot", "solara", "xeno", "wave", "cloudy", "tupical", "horizon", "myst", "celery", "zarora", 
    "juju", "nezure", "FusionHacks", "aimmy", "Fluxus", "clumsy", "MystW", "isabelle", "dx9ware", 
    "injector", "cheat", "hack", "esp", "aimbot", "exploit", "executor", "softaim", "d3d9.dll",
    "pcileech", "kdmapper", "vape", "phantom", "killaura", "usermode", "internal", 
    "external", "bypass", "loader", "spoofer", "hwid", "silent", "fov", "recoil", "nospread",
    "synapse", "krnl", "sentinel", "sirhurt", "skisploit", "comet", "oxygen u", "electron", "nihon", 
    "evon", "vega x", "delta", "arceus", "hydrogen", "codex", "valyse", "fluctus", "incognito",
    "scriptware", "sw-m", "ro-exec", "krampus", "macsploit"
)

# --- 3. FILESYSTEM FORENSICS (Prefetch & KeyAuth) ---
$log.Add("`n[SECTION 2: FILESYSTEM FORENSICS]")

# Prefetch Scan (FULL VISIBILITY MODE)
try {
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue

    if ($pfFiles) {
        $log.Add("--- Prefetch Scan (Full Execution History) ---")
        $log.Add("INFO: Total Prefetch Files: $($pfFiles.Count)")

        foreach ($pf in $pfFiles | Sort-Object LastWriteTime -Descending) {

            # Extract executable name (cleaner output)
            $exeName = ($pf.BaseName -split "-")[0]

            $log.Add("PREFETCH: $exeName | Last Run: $($pf.LastWriteTime)")
            
            # Optional: still flag suspicious names
            foreach ($w in $cheatBlacklist) {
                if ($exeName -ilike "*$w*") {
                    $log.Add("⚠️ FLAGGED: Suspicious Prefetch Entry -> $exeName")
                    $flags++
                    break
                }
            }
        }

        $log.Add("INFO: Prefetch scan completed successfully.")
    } else {
        $log.Add("WARNING: Prefetch directory empty or inaccessible.")
    }

} catch {
    $log.Add("FAIL: Prefetch access denied or scan error.")
}

# KeyAuth Check
try {
    if (Test-Path "C:\ProgramData\KeyAuth\debug") {
        $folders = Get-ChildItem "C:\ProgramData\KeyAuth\debug" -Directory
        foreach ($f in $folders) { $log.Add("FAIL: KeyAuth/Cheat Folder Detected: $($f.FullName)") }
    } else { $log.Add("PASS: No KeyAuth debug folders found.") }
} catch { $log.Add("INFO: KeyAuth path clean.") }

# --- 4. ROBLOX BOOTSTRAPPER AUDIT ---
$log.Add("`n[SECTION 3: ROBLOX BOOTSTRAPPER AUDIT]")

$bootstrapPaths = @(
    @{ Name = "Bloxstrap"; Path = "$env:LOCALAPPDATA\Bloxstrap\Settings.json" },
    @{ Name = "Fishstrap"; Path = "$env:LOCALAPPDATA\Fishstrap" },
    @{ Name = "Voidstrap"; Path = "$env:LOCALAPPDATA\Voidstrap" },
    @{ Name = "Plexity"; Path = "$env:LOCALAPPDATA\Plexity" }
)

$bootstrapDetected = $false

foreach ($b in $bootstrapPaths) {
    if (Test-Path $b.Path) {
        $bootstrapDetected = $true
        $log.Add("INFO: Detected Bootstrapper -> $($b.Name)")

        # Specific handling for Bloxstrap config
        if ($b.Name -eq "Bloxstrap" -and $b.Path -like "*.json") {
            try {
                $settings = Get-Content $b.Path -Raw | ConvertFrom-Json
                if ($null -eq $settings.CustomIntegrations -or $settings.CustomIntegrations.Count -eq 0) {
                    $log.Add("PASS: Bloxstrap Custom Integrations EMPTY")
                } else {
                    foreach ($ci in $settings.CustomIntegrations) {
                        $log.Add("FAIL: Bloxstrap Integration: $($ci.Name) -> $($ci.Location)")
                    }
                }
            } catch {
                $log.Add("WARNING: Bloxstrap config unreadable")
            }
        }
        else {
            # Generic handling for alternatives
            try {
                $files = Get-ChildItem $b.Path -Recurse -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    foreach ($w in $cheatBlacklist) {
                        if ($f.Name -ilike "*$w*") {
                            $log.Add("FAIL: Suspicious file in $($b.Name): $($f.FullName)")
                            $flags++
                        }
                    }
                }
            } catch {
                $log.Add("INFO: Could not fully scan $($b.Name)")
            }
        }
    }
}

if (-not $bootstrapDetected) {
    $log.Add("PASS: No known Roblox bootstrappers detected.")
}

# --- DEFENDER FULL SECURITY AUDIT ---
$log.Add("`n[SECTION 4: DEFENDER FULL SECURITY AUDIT]")

# Ensure flags exists
if (-not $flags) { $flags = 0 }

# -----------------------------
# 1. defender
# -----------------------------
try {
    $mp = Get-MpComputerStatus
    $pref = Get-MpPreference

    # Real-time protection
    if ($mp.RealTimeProtectionEnabled) {
        $log.Add("PASS: Real-time protection ON")
    } else {
        $log.Add("FAIL: Real-time protection OFF")
        $flags++
    }

    # Behavior monitoring
    if ($mp.BehaviorMonitorEnabled) {
        $log.Add("PASS: Behavior monitoring ON")
    } else {
        $log.Add("FAIL: Behavior monitoring OFF")
        $flags++
    }

    # IOAV (downloads scanning)
    if ($mp.IOAVProtectionEnabled) {
        $log.Add("PASS: IOAV protection ON")
    } else {
        $log.Add("FAIL: IOAV protection OFF")
        $flags++
    }

    # Cloud protection
    if (-not $pref.DisableBlockAtFirstSeen) {
        $log.Add("PASS: Cloud protection ON")
    } else {
        $log.Add("FAIL: Cloud protection OFF")
        $flags++
    }

} catch {
    $log.Add("FAIL: Could not read Defender status")
    $flags++
}

# -----------------------------
# 2. EXCLUSIONS 
# -----------------------------
try {
    if ($pref.ExclusionPath -or $pref.ExclusionProcess -or $pref.ExclusionExtension) {
        $log.Add("FAIL: Defender exclusions detected")

        foreach ($e in $pref.ExclusionPath) {
            $log.Add("EXCLUSION PATH: $e")
        }
        foreach ($e in $pref.ExclusionProcess) {
            $log.Add("EXCLUSION PROCESS: $e")
        }
        foreach ($e in $pref.ExclusionExtension) {
            $log.Add("EXCLUSION EXT: $e")
        }

        $flags++
    } else {
        $log.Add("PASS: No Defender exclusions")
    }
} catch {
    $log.Add("INFO: Could not read exclusions")
}

# -----------------------------
# 3. ALLOWED THREATS
# -----------------------------
try {
    if ($pref.ThreatIDDefaultAction_Ids) {
        $log.Add("FAIL: Allowed threats detected in Defender")
        $flags++
    } else {
        $log.Add("PASS: No allowed threats")
    }
} catch {
    $log.Add("INFO: Could not check allowed threats")
}

# -----------------------------
# 4. Regedit check
# -----------------------------
function Scan-RegistryTree {
    param ($BasePath, $Label)

    if (Test-Path $BasePath) {
        # Include root key + all children
        $allKeys = @()
        $allKeys += Get-Item $BasePath
        $allKeys += Get-ChildItem -Path $BasePath -Recurse -ErrorAction SilentlyContinue

        foreach ($key in $allKeys) {
            try {
                $values = $key.GetValueNames()

                foreach ($v in $values) {
                    if ($v -ne "") {
                        $log.Add("FAIL: $Label -> Value '$v' in $($key.Name)")
                        $flags++
                    }
                }

                $subkeys = Get-ChildItem $key.PSPath -ErrorAction SilentlyContinue
                foreach ($sk in $subkeys) {
                    $log.Add("FAIL: $Label -> Subkey exists: $($sk.PSChildName)")
                    $flags++
                }

            } catch {}
        }
    } else {
        $log.Add("PASS: $Label not present")
    }
}

Scan-RegistryTree "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction" "Threat Actions"
Scan-RegistryTree "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" "Exclusion Extensions"

# -----------------------------
# 5. NOTIFICATIONS CHECK (FIXED)
# -----------------------------
try {
    $notifKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"

    if (Test-Path $notifKey) {
        $subKeys = Get-ChildItem -Path $notifKey -ErrorAction SilentlyContinue

        $disabledFound = $false

        foreach ($sk in $subKeys) {
            try {
                $props = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue

                foreach ($p in $props.PSObject.Properties) {
                    if ($p.MemberType -eq "NoteProperty") {
                        if ($p.Value -eq 0) {
                            $log.Add("FAIL: Notifications disabled for $($sk.PSChildName) -> $($p.Name)")
                            $flags++
                            $disabledFound = $true
                        }
                    }
                }

            } catch {}
        }

        if (-not $disabledFound) {
            $log.Add("PASS: Notifications appear enabled")
        }

    } else {
        $log.Add("INFO: Notification settings not found")
    }

} catch {
    $log.Add("INFO: Could not verify notifications")
}
# --- 6. DEEP REGISTRY ENGINE (Exhaustive Scan) ---
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
    "HKCR:\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\Microsoft\Tracing",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
)

$flags = 0
foreach ($p in $regPaths) {
    if (Test-Path $p) {
        try {
            $item = Get-Item -Path $p -ErrorAction SilentlyContinue
            foreach ($name in $item.GetValueNames()) {
                foreach ($w in $cheatBlacklist) {
                    if ($name -ilike "*$w*") { 
                        $log.Add("FAIL: Registry Match [$w] in $p -> Name: $name")
                        $flags++
                    }
                }
            }
            $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            $props.PSObject.Properties | ForEach-Object {
                $val = $_.Value.ToString()
                foreach ($w in $cheatBlacklist) {
                    if ($val -ilike "*$w*") { 
                        $log.Add("FAIL: Registry Value Match [$w] in $p -> Value: $val")
                        $flags++
                    }
                }
            }
        } catch {}
    }
}

# --- 7. LIVE PROCESS AUDIT  ---
$log.Add("`n[SECTION 6: ACTIVE PROCESSES]")
$macroDetect = @("autohotkey", "ahk", "macro", "synapse", "logitech", "itask", "x-mouse", "tinytask", "autoclicker", "jitbit")
$recordDetect = @("obs64", "obs32", "streamlabs", "medal", "shadowplay", "nvcontainer", "NVIDIA Share", "bandicam", "fraps")

$procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
foreach ($proc in $procs) {
    $desc = ""; try { $desc = $proc.MainModule.FileVersionInfo.FileDescription } catch {}

    # Cheats (Failure)
    foreach ($c in $cheatBlacklist) {
        if ($proc.ProcessName -ilike "*$c*" -or $desc -ilike "*$c*") {
            $log.Add("FAIL: Active Cheat Process: $($proc.ProcessName) ($desc)")
            $flags++
        }
    }
    # Macros (Detection)
    foreach ($m in $macroDetect) {
        if ($proc.ProcessName -ilike "*$m*" -or $desc -ilike "*$m*") { $log.Add("INFO: Macro/Input Process: $($proc.ProcessName)") }
    }
    # Recording (Detection)
    foreach ($r in $recordDetect) {
        if ($proc.ProcessName -ilike "*$r*") {
            $rec = "IDLE"; try { if (($proc.Modules.ModuleName -match "nvenc|nvapi|obs|vce") -and ($proc.CPU -gt 0.01)) { $rec = "ACTIVE" } } catch {}
            $log.Add("INFO: Recorder Process [$($proc.ProcessName)] is $rec")
        }
    }
}
# --- DLL INJECTION HEURISTICS ---
$log.Add("`n[SECTION: DLL INJECTION HEURISTICS]")

foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
    try {
        $modules = $proc.Modules

        foreach ($m in $modules) {
            $path = $m.FileName.ToLower()

            # Suspicious locations
            if ($path -match "appdata|temp|roaming") {
                $log.Add("FAIL: Suspicious DLL in $($proc.ProcessName) -> $path")
                $flags++
            }

            # Known cheat keywords
            foreach ($w in $cheatBlacklist) {
                if ($path -like "*$w*") {
                    $log.Add("FAIL: Injected DLL match [$w] in $($proc.ProcessName)")
                    $flags++
                }
            }
        }
    } catch {}
}


# --- 8. PAH WINDOW (LIVE HISTORY) ---
Start-Job {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object Windows.Forms.Form
    $form.Text = "Process Active History (Live)"; $form.WindowState = 'Maximized'; $form.Topmost = $true
    $lb = New-Object Windows.Forms.ListBox; $lb.Dock = 'Fill'; $form.Controls.Add($lb)
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $timer = New-Object Windows.Forms.Timer; $timer.Interval = 2000
    $timer.Add_Tick({
        Get-Process | ForEach-Object {
            if (-not $seen.Contains($_.ProcessName)) {
                $seen.Add($_.ProcessName) | Out-Null
                $lb.Invoke([action]{ $lb.Items.Add("($(Get-Date -Format 'HH:mm:ss')) Launched: $($_.ProcessName)") })
            }
        }
    })
    $timer.Start(); [void]$form.ShowDialog()
} | Out-Null

# ======================================================
# REAL-TIME + MEMORY / HANDLE DETECTION (COMBINED)
# ======================================================

$log.Add("`n[SECTION: REAL-TIME + MEMORY DETECTION]")

$seen = @{}
$durationSeconds = 15   # how long to monitor (adjust if needed)
$endTime = (Get-Date).AddSeconds($durationSeconds)

while ((Get-Date) -lt $endTime) {

    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {

        $proc = $_
        $name = $proc.ProcessName.ToLower()

        # --- NEW PROCESS DETECTION ---
        if (-not $seen.ContainsKey($proc.Id)) {
            $seen[$proc.Id] = $true

            foreach ($w in $cheatBlacklist) {
                if ($name -like "*$w*") {
                    $log.Add("DETECTED: Live Process Match -> $name")
                    $flags++
                    break
                }
            }
        }

        # --- HANDLE COUNT CHECK ---
        try {
            if ($proc.HandleCount -gt 1000) {
                $log.Add("DETECTED: High Handle Count -> $name ($($proc.HandleCount))")
                $flags++
            }
        } catch {}

        # --- MEMORY USAGE CHECK ---
        try {
            if ($proc.WorkingSet -gt 500MB) {
                $log.Add("DETECTED: High Memory Usage -> $name")
                $flags++
            }
        } catch {}

    }

    Start-Sleep -Milliseconds 200
}

# --- 9. FINAL DISPATCH ---
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
                                                                                                                       
                                                                                                                       

DO NOT CLOSE "PAH (Process activity History)", if closed your recording will be Failed
"@
Write-Host $madeBy -ForegroundColor Red
Write-Host "                                         - Sub's Recording Policy" -ForegroundColor White
Write-Host "`n"

$body = @{ content = "Your message here" } | ConvertTo-Json
Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"



