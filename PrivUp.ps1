

$myGroups = @()
$groupInfo = whoami /groups /fo csv | ConvertFrom-Csv
foreach ($entry in $groupInfo) {
    $groupName = $entry."Group Name".Trim()
    $sid = $entry."SID".Trim()
    if ($groupName) {
        $myGroups += $groupName
    }
    if ($sid) {
        $myGroups += $sid
    }
}
$myGroups = $myGroups | Sort-Object -Unique
$myGroups += whoami

function Check_Path {
    Write-Host "`n[+] Checking PATH for DLL hijacking opportunities..." -ForegroundColor Yellow
    $env:Path -split ';' | ForEach-Object {
        $path = $_.Trim()
        try {
        if (-not (Test-Path -Path $path -ErrorAction SilentlyContinue)) {
            return
        }
        } catch {
            return
        }

        $acl = icacls $path 2>$null
        foreach ($line in $acl) {
            foreach ($group in $myGroups) {
                if ($path.StartsWith($env:USERPROFILE)){continue}
                if ($line -match [regex]::Escape($group) -and $line -match '(\(F\)|\(M\)|\(W\))') {
                    Write-Host "    [!] Writable directory in PATH: $path (group: $group)" -ForegroundColor Red
                }
            }
        }
    }
}

function Check-Perms($target) {
    $acls = icacls $target
    foreach ($line in $acls) {
        if ($line -like "$target*") {
        $line = $line.Substring($target.Length).Trim()
    }
        if ($line -match '^(?<user>.+?):\s*(?<perms>\(.+\))$') {
        $user = $matches['user'].Trim()
        $perms = $matches['perms'].Trim()
        foreach ($group in $myGroups) {
                if ($user -match [regex]::Escape($group) -and $perms -match '\([^\)]*[WMF][^\)]*\)') {					 
                    If (Test-Path $target -pathType container) {
                    $test_tmp_filename = "writetest.txt"
                    $test_filename = (Join-Path $target $test_tmp_filename)
                    Try { 
                        [io.file]::OpenWrite($test_filename).close()
                        Remove-Item -ErrorAction SilentlyContinue $test_filename
                        return $true
                    }
                    Catch {return $false}
                    }
                    return $true
                }
                }
            }
        }
    return $false
}

function Check_Services {
    Write-Host "`n[+] Checking services for hijacking opportunities..." -ForegroundColor Yellow

    $canShutdown = (whoami /priv | Select-String "SeShutdownPrivilege") -ne $null
    try{$servicesRaw = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop| Select-Object Name, StartMode, PathName}
    catch{
        Write-Host "    [!] Could not enumerate services" -ForegroundColor Magenta
    }
    $seenPaths = @{}
    if (Test-Path Variable:servicesRaw) {
        foreach ($svc in $servicesRaw) {
            $name = $svc.Name.Trim()
            $mode = $svc.StartMode.Trim()
            try{$pathname = $svc.PathName.Trim()}
            catch {continue}
            if (-not $pathname) { continue }
            $exePath = if ($pathname -match '^"([^"]+)"') { $matches[1] } else { ($pathname -split '\s',2)[0] }
            if (-not (Test-Path $exePath) -or $seenPaths.ContainsKey($exePath)) { continue }
            $seenPaths[$exePath] = $true
            $exeDir = Split-Path $exePath -Parent
            $canWriteExe = Check-Perms $exePath
            $canWriteDir = Check-Perms $exeDir
            if ($canWriteExe) {
                Write-Host "    [!] Writable service EXE: $exePath (Service: $name)" -ForegroundColor Red
            } elseif ($canWriteDir) {
                Write-Host "    [!] Writable service directory: $exeDir (Service: $name)" -ForegroundColor Red
            } else {continue}

            if ($mode -match 'Auto' -and $canShutdown) {
                Write-Host "        [+] Can restart machine to exploit service $name" -ForegroundColor Cyan
            } else {
                $startCheck = sc.exe continue $name
                if ($startCheck -contains "Access is denied") {
                    Write-Host "        [+] Can restart service '$name' manually" -ForegroundColor Cyan
                } else {
                    Write-Host "    [-] Cannot restart service '$name' (access denied)" -ForegroundColor Magenta
                }
            }
        }
    }
}

function Check_Installed{
    Write-Host "`n[+] Checking installed software for DLL hijacking possibilities..." -ForegroundColor Yellow
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($keyPath in $uninstallKeys) {
        $software = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue | 
            Select-Object DisplayName, InstallLocation | 
            Where-Object { $_.DisplayName -and $_.InstallLocation }
        foreach ($app in $software) {
            $displayName = $app.DisplayName
            $installPath = $app.InstallLocation.TrimEnd('\')
            try {
                if (-Not (Test-Path -Path $installPath -ErrorAction Stop)) {
                    continue
                }
            } catch {continue}
            $writeable = Check-Perms $installPath
            if ($writeable) {
                Write-Host "[!] Potential DLL hijack vector detected:" -ForegroundColor Red
                Write-Host "    Software     : $displayName"
                Write-Host "    Install Path : $installPath"
                Write-Host "    [!] You have write access to this directory! $installPath" -ForegroundColor Cyan
                Write-Host "    [!] This is only useful if a scheduled task\autorun starts this software" -ForegroundColor Cyan
            }
        }
    }
}

function Check_Processes{
    Write-Host "`n[+] Checking running processes for hijacking opportunities..." -ForegroundColor Yellow
    try{$processes = Get-WmiObject Win32_Process -ErrorAction Stop}
    catch{
        Write-Host "    [!] Could not enumerate processes" -ForegroundColor Magenta
    }
    $seenPaths = @{}
    if (Test-Path Variable:processes) {
        foreach ($proc in $processes) {
            $exePath = $proc.ExecutablePath
            $pid1 = $proc.ProcessId
            try {
            $owner = $proc.GetOwner()
            }
            catch{
            $owner = "system"
            }

            $runAsUser = "$($owner.Domain)\$($owner.User)"
            if ($runAsUser.Contains($env:USERNAME)){continue}
            if (-not $exePath -or -not (Test-Path $exePath -ErrorAction SilentlyContinue) -or $seenPaths.ContainsKey($exePath) ) { continue }
            $seenPaths[$exePath] = $true
            $exeDir = Split-Path $exePath -Parent
            $integrity = "Unknown"
            try {
                $integrity = (Get-Process -Id $pid1 -ErrorAction Stop).Path |
                    ForEach-Object { (Get-Acl $_).Owner }
            } catch {}
            
            $canWriteExe = Check-Perms $exePath
            $canWriteDir = Check-Perms $exeDir
            if ($canWriteExe -or $canWriteDir) {
                Write-Host "    [!] Potential Hijackable Process Detected" -ForegroundColor Red
                Write-Host "        [+] Process ID: $pid1"
                Write-Host "        [+] Executable: $exePath"
                Write-Host "        [+] Run As: $runAsUser"
                Write-Host "        [+] Integrity Level: $integrity"
                if ($canWriteExe) {
                    Write-Host "        [+] Writable EXE: $exePath" -ForegroundColor Red
                }
                if ($canWriteDir) {
                    Write-Host "        [+] Writable Directory: $exeDir" -ForegroundColor Red
                }
            }
        }
    }
}

function Test-Unquoted{
    param (
        [Parameter(Mandatory=$true)]
        [string]$exePath
    )
    $hijackablePaths = @()
        $segments = $exePath -split '\\'
        $currentPath = $segments[0]
        foreach ($segment in $segments[1..($segments.Count - 1)]) {
            $currentPath = Join-Path $currentPath $segment
            if ($currentPath -match '\s') {
                $check = Split-Path -Path $currentPath -Parent
                if (Check-Perms $check) {
                    $hijackablePaths += $check
                }
            }
        }
    return $hijackablePaths
}

function Check_Unquoted{
    Write-Host "`n[+] Searching for Unquoted Service Paths..." -ForegroundColor Yellow
    try{
        $val =  Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode -ErrorAction Stop| 
                Where {$_.PathName -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | 
                select Name,DisplayName,StartMode,PathName
        foreach ($service in $val) {
            if ($service.PathName -notmatch ' ') {continue}
            $path = ($service.PathName -split " -")[0]
            $hijackablePaths = Test-Unquoted -exePath $path
            if (-not $hijackablePaths) {continue}
            Write-Host "    [+] Found unquoted service path" -ForegroundColor Red
            Write-Host "        Name: $($service.Name)" 
            Write-Host "        DisplayName: $($service.DisplayName)" 
            Write-Host "        StartMode: $($service.StartMode)" 
            Write-Host "        PathName: $($path)" 
            foreach ($path in $hijackablePaths) {
                    Write-Host "        [!] Potential path hijack: Can write $path" -ForegroundColor Red
            }
        }
    }
    catch{
        Write-Host "    [!] Could not enumerate services" -ForegroundColor Magenta
    }
}

function Check_Passwords {
    Write-Host "`n[+] Password Hunting..." -ForegroundColor Yellow

    Write-Host "    [+] Checking stored creds" -ForegroundColor Yellow
    $cmdkeyOutput = cmdkey /list
    if (-not($cmdkeyOutput -match "\*\s*NONE\s*\*")) {
        Write-Host "    [!] Stored Credentials Found via cmdkey:" -ForegroundColor Red
        Write-Host "$cmdkeyOutput"
        Write-Host "    [!] Can exploit with 'vaultcmd /listcred' or mimikatz" -ForegroundColor cyan
    }

    Write-Host "    [+] Looking for unattended" -ForegroundColor Yellow
    $commonUnattendPaths = @(
        "C:\Windows\Panther",
        "C:\Windows\Panther\Unattend",
        "C:\Windows\System32\Sysprep",
        "C:\Sysprep",
        "C:\"
    )
    foreach ($path in $commonUnattendPaths) {
    if (Test-Path $path) {
            Get-ChildItem -Path $path -Filter unattend.xml -ErrorAction SilentlyContinue -Force | ForEach-Object {
                $fullPath = Join-Path -Path $path -ChildPath "unattend.xml"
                Write-Host "        [!] Found unattend.xml at: $fullPath" -ForegroundColor Red
                try {
                    [xml]$xml = Get-Content $fullPath -ErrorAction Stop
                    $xml.SelectNodes("//*[contains(local-name(), 'password')]") | ForEach-Object {
                        Write-Host "        [+] Password Field: $($_.OuterXml)" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "        [!] Failed to parse XML in: $fullPath" -ForegroundColor Magenta
                }
            }
        }
    }

    Write-Host "    [+] Looking for groups.xml" -ForegroundColor Yellow
    $groupsXmlFiles = Get-ChildItem -Path "C:\Windows\SYSVOL\domain\Policies\*\Machine\Preferences\Groups\Groups.xml" -ErrorAction SilentlyContinue
    if ($groupsXmlFiles) {
        Write-Host "        [+] Found groups.xml files:" -ForegroundColor Red
        foreach ($file in $groupsXmlFiles) {
            Write-Host "        $file.FullName" -ForegroundColor Red
        }
    } 

    Write-Host "    [+] Looking for autologon" -ForegroundColor Yellow
    $autoLogon = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($autoLogon) {
        $autoLogonProps = $autoLogon.GetValueNames() | Where-Object { $_ -match 'pass' -and -not $_ -match 'PasswordExpiryWarning' }
        if ($autoLogonProps) {
            Write-Host "        [!] Autologon configuration found!" -ForegroundColor Red
            foreach ($prop in $autoLogonProps) {
                $val = $autoLogon.GetValue($prop)
                Write-Host "        [+] $prop = $val" -ForegroundColor Red
            }
            Write-Host "        [+] Can manually enumerate with 'Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon''" -ForegroundColor Red
        }
    }

    Write-Host "    [+] Looking for Powershell History" -ForegroundColor Yellow
    $users = Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue
    foreach ($user in $users) {
        $psReadlineDir = Join-Path -Path $user.FullName -ChildPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline'

        if (Test-Path $psReadlineDir -ErrorAction SilentlyContinue) {
            $historyFiles = Get-ChildItem -Path $psReadlineDir -File -ErrorAction SilentlyContinue
            if (-not $historyFiles.Count -gt 0) {continue}
            foreach ($file in $historyFiles) {
                Write-Host "    [+] PowerShell history found for user: $($user.Name)" -ForegroundColor Red
                try {
                    Write-Host "_____START CONTENT_____"
                    Get-Content -Path $file.FullName -ErrorAction Stop | ForEach-Object { Write-Host $_ }
                    Write-Host "_____END CONTENT_____"
                }
                catch {continue}
            }
        }
    }
}

function Check_Scheduled{
    Write-Host "`n[+] Checking Scheduled Tasks..."  -ForegroundColor Yellow
    $tasks = Get-ScheduledTask
    $CurrentUser = "$env:USERNAME"

    foreach ($task in $tasks) {
        $taskName   = $task.TaskName
        $taskPath = $task.TaskPath
        $fullCommand   = $task.Actions[0].Execute
        $runAsUser  = $task.Principal.UserId
        $logonType = $task.Principal.LogonType
        if ($logonType -eq "Password") {
            Write-Host "    [!] Task uses STORED credentials: $taskPath$taskName" -ForegroundColor Red
        }
        if ($runAsUser -match "$CurrentUser") {continue}
        $exePath = if ($fullCommand -match '^"([^"]+)"') {
            $matches[1]
        } elseif ($fullCommand -match '^(.*?\.exe)') {
            $matches[1]
        } else {
            ($fullCommand -split '\s',2)[0]
        }

        $exePath = [Environment]::ExpandEnvironmentVariables($exePath)
        if (-not $exePath) {continue}
        if (-not (Test-Path $exePath)) {continue}
        $exeDir = Split-Path $exePath -Parent
        $writeable = Check-Perms $exePath
        $dirWrite  = Check-Perms $exeDir
        $hasSpaces = $exePath -match '\s'
        $isQuoted = $fullCommand.Trim().StartsWith('"') -and $fullCommand.Trim().EndsWith('"')
        $unquotedWithSpaces = $hasSpaces -and -not $isQuoted

        if ($writeable -or $dirWrite -or $unquotedWithSpaces) {
            $hijackablePaths = Test-Unquoted -exePath $exePath
            if ($unquotedWithSpaces -and (-not $hijackablePaths)){continue}
                Write-Host "    [*] Potentially exploitable task:"-ForegroundColor Red
                Write-Host "        Task Name   : $taskName"
                Write-Host "        Run As User: $runAsUser"
                Write-Host "        Task To Run: $fullCommand"
                Write-Host "        EXE Path    : $exePath"
                if ($writeable) { Write-Host "    [!] Write access to EXE" -ForegroundColor Red} 
                if ($dirWrite)  { Write-Host "    [!] Write access to directory"  -ForegroundColor Red}
                if ($unquotedWithSpaces) { 
                    foreach ($path in $hijackablePaths) {
                        Write-Host "    [!] Potential unquoted path hijack: Can write $path" -ForegroundColor Red
                    }
                    }
            
        }
    }
}

function Check_Startup {
    Write-Host "`n[+] Checking Startup Tasks..."  -ForegroundColor Yellow

    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $entries = Get-ItemProperty -Path $path
            if ($entries.PSObject.Properties.Count -gt 5) {
                Write-Host "`n$path"
                foreach ($entry in $entries.PSObject.Properties) {
                    if ($entry.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                        Write-Host "	[+]Found Registry $($entry.Name) = $($entry.Value)" -ForegroundColor Red
                    }
                }
            }
        } 
    }
    $startupFolder = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startupFolder) {
        $files = Get-ChildItem -Path $startupFolder
        if (-not($files.Count -eq 0)) {
            Write-Host "	[+]Startup items in $startupFolder" -ForegroundColor Red
            $files | ForEach-Object { Write-Host "		[+] $($_.Name)" -ForegroundColor Cyan}
        }
    }
    $gpScriptPath = "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup"
    if (Test-Path $gpScriptPath) {
        $scriptFiles = Get-ChildItem -Path $gpScriptPath
        if (-not($scriptFiles.Count -eq 0)) {
            Write-Host "	[+]Group Policy startup scripts" -ForegroundColor Red
            $scriptFiles | ForEach-Object { Write-Host "		[+] $($_.Name)" -ForegroundColor Cyan}
        }
    }
}

function Check_misc {
    Write-Host "`n[+] Checking Some random stuf..." -ForegroundColor Yellow
    $hkcu = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue

    $hkcuValue = $hkcu.AlwaysInstallElevated
    $hklmValue = $hklm.AlwaysInstallElevated

    if ($hkcuValue -eq 1 -and $hklmValue -eq 1) {
        Write-Host "    [!] AlwaysInstallElevated is ENABLED in both HKCU and HKLM!" -ForegroundColor Red
        Write-Host "    [+]You may be able to escalate privileges by installing an MSI as SYSTEM." -ForegroundColor Red
    } 

    $hivePaths = @(
        "$env:SystemRoot\System32\config\SAM",
        "$env:SystemRoot\System32\config\SYSTEM",
        "$env:SystemRoot\System32\config\SECURITY"
    )
    foreach ($hive in $hivePaths) {
        try {
            $stream = [System.IO.File]::Open($hive, 'Open', 'Read', 'None')
            if ($stream) {
                Write-Host "    [!] Hive readable: $hive" -ForegroundColor Red
                $stream.Close()
            }
        } catch {}
        
    }
    $tempPath = "$env:TEMP\reg_dumps"
    New-Item -Path $tempPath -ItemType Directory -Force | Out-Null

    $hives = @{
        "HKLM\SAM"      = "$tempPath\SAM.save"
        "HKLM\SYSTEM"   = "$tempPath\SYSTEM.save"
        "HKLM\SECURITY" = "$tempPath\SECURITY.save"
    }

    foreach ($hive in $hives.Keys) {
        $outputFile = $hives[$hive]
        try {
            $result = reg save $hive $outputFile /y 2>&1
            if (Test-Path $outputFile) {
                Write-Host "    [!] SUCCESS: Able to save $hive to $outputFile" -ForegroundColor Red
            } 
        } catch {}
    }
    $services = Get-WmiObject -Class Win32_Service
    foreach ($service in $services) {
        $serviceName = $service.Name
        $displayName = $service.DisplayName

        try {
            $sd = Get-Acl -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $serviceName)
            foreach ($entry in $sd.Access) {
                if ($entry.IdentityReference -match "$env:USERNAME") {
                    Write-Host "    [!] You can modify service: $displayName ($serviceName)" -ForegroundColor Red
                    Write-Host "    User            : $($entry.IdentityReference)"
                    Write-Host "    RegistryRights  : $($entry.RegistryRights)"
                    Write-Host "    AccessControl   : $($entry.AccessControlType)"
                }
            }
        } catch {}
    }

}

Check_Path
Check_Services
Check_Installed
Check_Unquoted
Check_Processes
Check_Passwords
Check_Scheduled
Check_Startup
Check_misc