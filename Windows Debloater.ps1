# Create Logs directory in Documents if it doesn't exist
$logDirectory = "$env:USERPROFILE\Documents\Logs"
if (!(Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory | Out-Null
}

# Define log files
$fullLog = "$logDirectory\FullLog.txt"
$errorLog = "$logDirectory\ErrorLog.txt"
$changeLog = "$logDirectory\ChangeLog.txt"

# Logging Setup
function Log-Message {
    param (
        [string]$message,
        [string]$logLevel = "Info",
        [switch]$error,
        [switch]$change
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $logLevel - $message"

    # Write to Full Log
    Add-Content -Path $fullLog -Value $logEntry

    # Write to Error Log if error
    if ($error) {
        Add-Content -Path $errorLog -Value $logEntry
    }

    # Write to Change Log if change
    if ($change) {
        Add-Content -Path $changeLog -Value $logEntry
    }

    # Output to console based on log level
    if ($logLevel -eq "Error") {
        Write-Host $message -ForegroundColor Red
    } elseif ($logLevel -eq "Warning") {
        Write-Host $message -ForegroundColor Yellow
    } else {
        Write-Host $message -ForegroundColor Cyan
    }
}

# Admin Check Function
function Ensure-Admin {
    $currentUser = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Log-Message "This script requires administrator privileges." -logLevel Warning
        Write-Host "This script requires administrator privileges." -ForegroundColor Yellow
        Write-Host "Press any key to exit..." -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }
}

# Windows Version Check - Complete rewrite with multiple detection methods
function Check-WindowsVersion {
    try {
        # Method 1: Using Environment.OSVersion
        $winVer = [System.Environment]::OSVersion.Version
        Write-Host "Debug - Raw Windows Version: Major=$($winVer.Major), Minor=$($winVer.Minor), Build=$($winVer.Build)" -ForegroundColor Yellow
        
        # Method 2: Using WMI/CIM
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $caption = $osInfo.Caption
        $buildNumber = $osInfo.BuildNumber
        Write-Host "Debug - WMI OS Info: $caption (Build $buildNumber)" -ForegroundColor Yellow
        
        # Method 3: Registry check for Windows 11
        $productName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
        Write-Host "Debug - Registry Product Name: $productName" -ForegroundColor Yellow
        
        # Force Windows 11 detection for build 26100
        if ($winVer.Build -ge 22000) {
            Log-Message "Windows 11 detected (Build $($winVer.Build))." -logLevel Info
            return "Windows 11"
        }
        # Check if OS is "Windows 11"
        elseif ($productName -like "*Windows 11*" -or $caption -like "*Windows 11*") {
            Log-Message "Windows 11 detected via product name." -logLevel Info
            return "Windows 11"
        }
        # Windows 10
        elseif ($winVer.Major -eq 10 -and $winVer.Build -lt 22000) {
            Log-Message "Windows 10 detected (Build $($winVer.Build))." -logLevel Info
            return "Windows 10"
        }
        # Windows 8.1
        elseif ($winVer.Major -eq 6 -and $winVer.Minor -eq 3) {
            Log-Message "Windows 8.1 detected." -logLevel Info
            return "Windows 8.1"
        }
        # Windows 8
        elseif ($winVer.Major -eq 6 -and $winVer.Minor -eq 2) {
            Log-Message "Windows 8 detected." -logLevel Info
            return "Windows 8"
        }
        # Fallback for Windows 11 with unusual version numbers (like Insider builds)
        elseif ($winVer.Build -ge 20000) {
            Log-Message "Windows 11 detected (likely Insider build $($winVer.Build))." -logLevel Info
            return "Windows 11"
        }
        # Last resort - force Windows 11 for build 26100
        elseif ($buildNumber -eq "26100") {
            Log-Message "Windows 11 detected (Build 26100 - forced detection)." -logLevel Info
            return "Windows 11"
        }
        # Unsupported
        else {
            Log-Message "Unsupported Windows version detected." -logLevel Error -error
            Write-Host "Unsupported Windows version detected." -ForegroundColor Red
            Write-Host "This tool supports Windows 8, 8.1, 10, and 11 only." -ForegroundColor Red
            
            # Emergency override - ask the user
            Write-Host "`nEmergency override: Please select your Windows version:" -ForegroundColor Yellow
            Write-Host "1. Windows 8" -ForegroundColor White
            Write-Host "2. Windows 8.1" -ForegroundColor White
            Write-Host "3. Windows 10" -ForegroundColor White
            Write-Host "4. Windows 11" -ForegroundColor White
            
            $userChoice = Read-Host "Enter your choice (1-4)"
            
            switch ($userChoice) {
                "1" { return "Windows 8" }
                "2" { return "Windows 8.1" }
                "3" { return "Windows 10" }
                "4" { return "Windows 11" }
                default { 
                    Write-Host "Invalid choice. Exiting..." -ForegroundColor Red
                    exit
                }
            }
        }
    }
    catch {
        Log-Message "Error detecting Windows version: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Error detecting Windows version: $($_.Exception.Message)" -ForegroundColor Red
        
        # Emergency override - ask the user
        Write-Host "`nEmergency override: Please select your Windows version:" -ForegroundColor Yellow
        Write-Host "1. Windows 8" -ForegroundColor White
        Write-Host "2. Windows 8.1" -ForegroundColor White
        Write-Host "3. Windows 10" -ForegroundColor White
        Write-Host "4. Windows 11" -ForegroundColor White
        
        $userChoice = Read-Host "Enter your choice (1-4)"
        
        switch ($userChoice) {
            "1" { return "Windows 8" }
            "2" { return "Windows 8.1" }
            "3" { return "Windows 10" }
            "4" { return "Windows 11" }
            default { 
                Write-Host "Invalid choice. Exiting..." -ForegroundColor Red
                exit
            }
        }
    }
}



# Create System Restore Point
function Create-RestorePoint {
    try {
        # Check if System Restore is enabled
        $srEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($null -eq $srEnabled) {
            Log-Message "System Restore is not enabled on this system." -logLevel Warning
            Write-Host "System Restore is not enabled on this system." -ForegroundColor Yellow
            Write-Host "Do you want to continue without creating a restore point? (Y/N)" -ForegroundColor Yellow
            $response = Read-Host
            if ($response -notmatch "^[Yy]$") {
                Log-Message "User chose to exit due to System Restore being disabled." -logLevel Info
                exit
            }
            return
        }
        
        # Modify the system restore point frequency to 30 minutes (1800 seconds)
        try {
            # Create the registry path if it doesn't exist
            $restorePointFrequencyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
            if (!(Test-Path $restorePointFrequencyPath)) {
                New-Item -Path $restorePointFrequencyPath -Force | Out-Null
            }
            
            # Set the restore point frequency to 30 minutes (1800 seconds)
            Set-ItemProperty -Path $restorePointFrequencyPath -Name "SystemRestorePointCreationFrequency" -Value 30 -Type DWord -Force
            Log-Message "System restore point frequency set to 30 minutes" -logLevel Info
            Write-Host "System restore point frequency set to 30 minutes" -ForegroundColor Green
        }
        catch {
            Log-Message "Failed to modify restore point frequency: $($_.Exception.Message)" -logLevel Warning
            Write-Host "Failed to modify restore point frequency. Will attempt to create restore point anyway." -ForegroundColor Yellow
        }
        
        # Check if a restore point named "Before Debloating" already exists
        $restorePoints = Get-ComputerRestorePoint | Where-Object { $_.Description -eq "Before Debloating" }
        
        # Create the restore point
        Log-Message "Creating system restore point..." -logLevel Info
        Checkpoint-Computer -Description "Before Debloating" -RestorePointType "APPLICATION_INSTALL" -ErrorAction Stop
        Log-Message "System restore point created successfully!" -logLevel Info
        Write-Host "System restore point created successfully!" -ForegroundColor Green
        
        # Reset the frequency back to default (24 hours = 1440 minutes)
        try {
            Set-ItemProperty -Path $restorePointFrequencyPath -Name "SystemRestorePointCreationFrequency" -Value 1440 -Type DWord -Force
            Log-Message "System restore point frequency reset to default (24 hours)" -logLevel Info
        }
        catch {
            Log-Message "Failed to reset restore point frequency: $($_.Exception.Message)" -logLevel Warning
        }
    } catch {
        Log-Message "Failed to create system restore point: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Failed to create system restore point!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Proceeding without a restore point..." -ForegroundColor Yellow
        Write-Host "Press any key to continue..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}


# Hardware Detection
function Detect-CPU-GPU {
    try {
        $cpu = (Get-CimInstance Win32_Processor).Name
        $gpu = (Get-CimInstance Win32_VideoController).Name
        Log-Message "Detected CPU: $cpu" -logLevel Info
        Log-Message "Detected GPU: $gpu" -logLevel Info
        return @{CPU=$cpu; GPU=$gpu}
    } catch {
        Log-Message "Failed to detect hardware: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Failed to detect hardware!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return @{CPU="Unknown"; GPU="Unknown"}
    }
}

# CPU & GPU Optimization
function Optimize-CPU-GPU {
    try {
        $hardware = Detect-CPU-GPU
        Log-Message "Starting CPU & GPU optimization" -logLevel Info
        
        Write-Host "`n⚠️ PERFORMANCE OPTIMIZATION WARNINGS ⚠️" -ForegroundColor Red
        Write-Host "These optimizations can:" -ForegroundColor Yellow
        Write-Host "- Increase power consumption and heat generation" -ForegroundColor Red
        Write-Host "- Potentially reduce hardware lifespan" -ForegroundColor Red
        Write-Host "- Cause system instability if cooling is insufficient" -ForegroundColor Red
        Write-Host "- Impact battery life on laptops" -ForegroundColor Red
        
        function Apply-Change {
            param (
                [string]$description,
                [string]$warning,
                [scriptblock]$command
            )
            Write-Host "`nOptimization: $description" -ForegroundColor Yellow
            Write-Host "Warning: $warning" -ForegroundColor Red
            $response = Read-Host "Apply this optimization? (Y/N)"
            if ($response -match "^[Yy]$") {
                try {
                    & $command
                    Log-Message "Successfully applied: $description" -logLevel Info -change
                    Write-Host "Successfully applied!" -ForegroundColor Green
                } catch {
                    Log-Message "Failed to apply: $description - Error: $($_.Exception.Message)" -logLevel Error -error
                    Write-Host "Failed to apply!" -ForegroundColor Red
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Log-Message "Skipped: $description" -logLevel Info
                Write-Host "Skipped." -ForegroundColor Yellow
            }
        }

        # Power Plan Optimization
        Apply-Change "Set High Performance Power Plan" "Will increase power consumption" {
            powercfg /s SCHEME_MIN
        }
        
        # CPU Optimizations
        Apply-Change "Disable Core Parking" "May increase CPU temperature" {
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v Attributes /t REG_DWORD /d 0 /f
        }
        
        Apply-Change "Disable CPU Throttling" "Could lead to thermal issues" {
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f
        }
        
        # GPU Optimizations
        if ($hardware.GPU -match "NVIDIA") {
            Apply-Change "NVIDIA GPU Optimization" "May affect stability" {
                reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f
            }
        } elseif ($hardware.GPU -match "AMD") {
            Apply-Change "AMD GPU Optimization" "May affect stability" {
                reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f
            }
        }
        
        Log-Message "Completed CPU & GPU optimization" -logLevel Info
    } catch {
        Log-Message "Error during CPU & GPU optimization: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Error during CPU & GPU optimization!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Windows Defender Removal
function Remove-WindowsDefender {
    try {
        Log-Message "Starting Windows Defender removal" -logLevel Warning
        
        # Check Windows version for compatibility
        $winVer = [System.Environment]::OSVersion.Version
        $windowsVersion = Check-WindowsVersion
        
        # Modify the function to handle different Windows versions
        if ($windowsVersion -eq "Windows 8" -or $windowsVersion -eq "Windows 8.1") {
            Log-Message "Windows Defender removal on Windows 8/8.1 requires different approach" -logLevel Warning
            Write-Host "Windows Defender on Windows 8/8.1 works differently than on Windows 10/11." -ForegroundColor Yellow
            Write-Host "This operation will disable Windows Defender features available on your system." -ForegroundColor Yellow
        }
        
        Write-Host "`n⚡ WINDOWS DEFENDER REMOVAL ⚡" -ForegroundColor Red
        Write-Host "⚠️ WARNING: THIS IS A CRITICAL OPERATION ⚠️" -ForegroundColor Red
        Write-Host "Disabling Windows Defender will significantly reduce your system's security." -ForegroundColor Yellow
        Write-Host "Please ensure you have alternative antivirus protection installed." -ForegroundColor Yellow
        
        Write-Host "`n⚠️ SPECIFIC RISKS:" -ForegroundColor Red
        Write-Host "- Real-time protection will be disabled" -ForegroundColor Red
        Write-Host "- Virus & threat protection will be turned off" -ForegroundColor Red
        Write-Host "- Your system will be more vulnerable to malware" -ForegroundColor Red
        Write-Host "- You MUST have alternative security software installed" -ForegroundColor Red
        
        Write-Host "`n⚠️ IMPORTANT:" -ForegroundColor Yellow
        Write-Host "If you proceed without proper alternative security software," -ForegroundColor Yellow
        Write-Host "your system will be at significant risk of infection!" -ForegroundColor Yellow
        
        Write-Host "`n⚠️ ARE YOU ABSOLUTELY SURE YOU WANT TO PROCEED?" -ForegroundColor Red
        Write-Host "Type 'CONFIRM' to disable Windows Defender (not recommended!)" -ForegroundColor Red
        Write-Host "Or type anything else to cancel this operation." -ForegroundColor Yellow
        
        # Add a countdown to give the user time to reconsider
        Write-Host "`n⚠️ FINAL WARNING: 10 SECOND COUNTDOWN" -ForegroundColor Red
        for ($i = 10; $i -gt 0; $i--) {
            Write-Host "Proceeding in... $i seconds" -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            if ($Host.UI.RawUI.KeyAvailable -and (Read-Host -Prompt "Press 'N' to cancel") -match "^[Nn]$") {
                Log-Message "Windows Defender removal cancelled" -logLevel Info
                Write-Host "Operation cancelled." -ForegroundColor Green
                return
            }
        }
        
        $confirm = Read-Host "`nEnter 'CONFIRM' to proceed (NOT RECOMMENDED)"
        if ($confirm -eq "CONFIRM") {
            try {
                # Method varies based on Windows version
                if ($windowsVersion -eq "Windows 8" -or $windowsVersion -eq "Windows 8.1") {
                    # Windows 8/8.1 method
                    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
                        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
                    
                    Log-Message "Windows Defender disabled on Windows 8/8.1" -logLevel Warning -change
                    Write-Host "Windows Defender disabled successfully!" -ForegroundColor Green
                } 
                else {
                    # Windows 10/11 method
                    # Check if the policy key exists, if not create it
                    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
                        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
                    
                    # Create Real-Time Protection key if it doesn't exist
                    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
                        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
                    Log-Message "Windows Defender disabled on Windows 10/11" -logLevel Warning -change
                    Write-Host "Windows Defender disabled successfully!" -ForegroundColor Green
                }
            } catch {
                Log-Message "Failed to disable Windows Defender: $($_.Exception.Message)" -logLevel Error -error
                Write-Host "Error disabling Windows Defender!" -ForegroundColor Red
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Log-Message "Windows Defender removal cancelled" -logLevel Info
            Write-Host "Operation cancelled." -ForegroundColor Yellow
        }
    } catch {
        Log-Message "Error during Windows Defender removal: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Error during Windows Defender removal!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# App Removal Utility - Modified to support older Windows versions
function Remove-Apps {
    try {
        Log-Message "Starting app removal" -logLevel Info
        
        Write-Host "`n🗑️ MICROSOFT BLOATWARE REMOVAL 🗑️" -ForegroundColor Cyan
        Write-Host "Removing common Microsoft bloatware that comes with Windows..." -ForegroundColor Yellow

        # Stop Edge processes first
        Write-Host "Stopping Edge processes..." -ForegroundColor Yellow
        Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

        $totalSuccess = 0
        $totalFailed = 0

        # Use DISM to remove provisioned packages
        Write-Host "`nRemoving provisioned packages..." -ForegroundColor Yellow
        $packages = @(
            "Microsoft.Edge",
            "Microsoft.MicrosoftEdge",
            "Microsoft.EdgeWebView",
            "Microsoft.3DBuilder",
            "Microsoft.WindowsAlarms",
            "Microsoft.WindowsCommunicationsApps",
            "Microsoft.WindowsCamera",
            "Microsoft.Office.OneNote",
            "Microsoft.SkypeApp",
            "Microsoft.Getstarted",
            "Microsoft.ZuneMusic",
            "Microsoft.WindowsMaps",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.BingFinance",
            "Microsoft.ZuneVideo",
            "Microsoft.BingNews",
            "Microsoft.Office.OneNote",
            "Microsoft.People",
            "Microsoft.WindowsPhone",
            "Microsoft.Windows.Photos",
            "Microsoft.BingSports",
            "Microsoft.WindowsSoundRecorder",
            "Microsoft.Office",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.Teams"
        )

        foreach ($package in $packages) {
            Write-Host "Removing $package..." -ForegroundColor Yellow
            try {
                # Remove for current user
                Get-AppxPackage -Name "*$package*" | Remove-AppxPackage -ErrorAction SilentlyContinue

                # Remove for all users
                Get-AppxPackage -AllUsers -Name "*$package*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

                # Remove provisioned package
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$package*" | 
                    Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

                $totalSuccess++
                Log-Message "Successfully removed: $package" -logLevel Info -change
            }
            catch {
                $totalFailed++
                Log-Message "Failed to remove $package" -logLevel Error -error
            }
        }

        # Edge-specific removal
        Write-Host "`nRemoving Microsoft Edge..." -ForegroundColor Yellow
        try {
            # Remove Edge using setup.exe
            $edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe"
            if (Test-Path $edgePath) {
                $setupExe = Get-Item $edgePath | Select-Object -ExpandProperty FullName
                if ($setupExe) {
                    Start-Process -FilePath $setupExe -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
                    Log-Message "Edge uninstallation attempted via setup.exe" -logLevel Info
                }
            }

            # Remove Edge services
            $services = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
            foreach ($service in $services) {
                if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    sc.exe delete $service
                }
            }

            # Remove Edge directories
            $edgePaths = @(
                "${env:ProgramFiles(x86)}\Microsoft\Edge",
                "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate",
                "${env:LOCALAPPDATA}\Microsoft\Edge",
                "${env:LOCALAPPDATA}\Microsoft\EdgeUpdate"
            )
            foreach ($path in $edgePaths) {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            Log-Message "Error removing Edge: $($_.Exception.Message)" -logLevel Error -error
        }

        Write-Host "`n✅ Bloatware removal complete!" -ForegroundColor Green
        Write-Host "Successfully processed $totalSuccess items, Failed to process $totalFailed items" -ForegroundColor Cyan
        Log-Message "Completed app removal: Success: $totalSuccess, Failed: $totalFailed" -logLevel Info
    }
    catch {
        Log-Message "Error during app removal: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Error during app removal!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`nPress any key to return to the main menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}



# Network Optimization
function Optimize-Network {
    try {
        Log-Message "Starting network optimization" -logLevel Info
        $windowsVersion = Check-WindowsVersion
        
        Write-Host "`n🌐 NETWORK OPTIMIZATION 🌐" -ForegroundColor Cyan
        Write-Host "Applying optimal TCP/IP settings for better performance..." -ForegroundColor Yellow
        
        # Detect connection types
        $connections = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        $hasWifi = $connections | Where-Object {$_.InterfaceDescription -match "wireless|wifi|wi-fi"}
        $hasEthernet = $connections | Where-Object {$_.InterfaceDescription -match "ethernet|gigabit|lan"}
        
        Write-Host "`nDetected Network Connections:" -ForegroundColor Cyan
        foreach ($conn in $connections) {
            $type = if ($conn.InterfaceDescription -match "wireless|wifi|wi-fi") { "WiFi" } else { "Ethernet" }
            $speed = $conn.LinkSpeed
            Write-Host "- $($conn.Name) ($type): $speed" -ForegroundColor White
        }
        
        Write-Host "`nApplying optimal TCP/IP settings..." -ForegroundColor Yellow
        
        try {
            # Common optimizations for all connection types
            
            # 1. Set TCP global parameters
            Write-Host "Setting TCP global parameters..." -ForegroundColor White
            netsh int tcp set global autotuninglevel=normal
            netsh int tcp set global congestionprovider=ctcp
            netsh int tcp set global ecncapability=enabled
            
            # 2. Set TCP chimney offload (hardware acceleration)
            netsh int tcp set global chimney=enabled
            
            # 3. Set TCP window sizes
            netsh int tcp set global rss=enabled
            
            # 4. Optimize receive-side scaling
            netsh int tcp set global rsc=enabled
            
            # 5. Set TCP timestamps
            netsh int tcp set global timestamps=disabled
            
            # 6. Set TCP initial RTT
            netsh int tcp set global initialRto=2000
            
            # 7. Registry optimizations
            Write-Host "Applying registry optimizations..." -ForegroundColor White
            
            # Create or ensure TCP/IP parameters key exists
            if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Force | Out-Null
            }
            
            # TCP/IP optimizations
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Value 64 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDupAcks" -Value 2 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts" -Value 1 -Type DWord -Force
            
            # 8. Connection-specific optimizations
            foreach ($conn in $connections) {
                $interfaceIndex = $conn.ifIndex
                $interfaceName = $conn.Name
                $isWifi = $conn.InterfaceDescription -match "wireless|wifi|wi-fi"
                
                Write-Host "`nOptimizing $interfaceName ($(if ($isWifi) {"WiFi"} else {"Ethernet"}))..." -ForegroundColor Cyan
                
                # Get connection speed
                $speed = $conn.LinkSpeed
                $speedValue = [int]($speed -replace "[^0-9]", "")
                $speedUnit = if ($speed -match "Gbps") { "Gbps" } else { "Mbps" }
                
                # Convert to Mbps for calculation
                if ($speedUnit -eq "Gbps") {
                    $speedMbps = $speedValue * 1000
                } else {
                    $speedMbps = $speedValue
                }
                
                Write-Host "Connection speed: $speed" -ForegroundColor White
                
                # Calculate optimal values based on connection speed
                $receiveWindow = [Math]::Min([Math]::Max(($speedMbps * 128), 65536), 16777216)
                
                # WiFi specific optimizations
                if ($isWifi) {
                    Write-Host "Applying WiFi-specific optimizations..." -ForegroundColor White
                    
                    # Set power saving to maximum performance
                    $powerMgmtKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\19cbb8fa-5279-450e-9fac-8a3d5fedd0c1\12bbebe6-58d6-4636-95bb-3217ef867c1a"
                    if (!(Test-Path $powerMgmtKey)) {
                        New-Item -Path $powerMgmtKey -Force | Out-Null
                    }
                    Set-ItemProperty -Path $powerMgmtKey -Name "Attributes" -Value 2 -Type DWord -Force
                    
                    # Disable power saving for WiFi adapter
                    $adapterPowerKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\$($conn.DeviceID)\PowerManagement"
                    if (Test-Path $adapterPowerKey) {
                        Set-ItemProperty -Path $adapterPowerKey -Name "AllowComputerToTurnOffDevice" -Value 0 -Type DWord -Force
                    }
                    
                    # Set WiFi autoconfig
                    netsh wlan set autoconfig enabled=yes interface="$interfaceName"
                    
                    # Optimize for WiFi (slightly smaller receive window)
                    $receiveWindow = [Math]::Min($receiveWindow, 4194304)
                }
                # Ethernet specific optimizations
                else {
                    Write-Host "Applying Ethernet-specific optimizations..." -ForegroundColor White
                    
                    # Enable jumbo frames for Gigabit+ connections
                    if ($speedMbps -ge 1000) {
                        $mtuSize = 9014
                        netsh interface ipv4 set subinterface $interfaceIndex mtu=$mtuSize store=persistent
                        Write-Host "Enabled Jumbo Frames (MTU=$mtuSize)" -ForegroundColor Green
                    }
                    
                    # Disable interrupt moderation for gaming/low-latency scenarios
                    $adapterKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\$($conn.DeviceID)"
                    if (Test-Path $adapterKey) {
                        Set-ItemProperty -Path $adapterKey -Name "*InterruptModeration" -Value 0 -Type DWord -Force
                    }
                }
                
                # Apply calculated receive window
                netsh int tcp set supplemental template=custom icw=10 receivewindow=$receiveWindow
                
                # Apply QoS settings
                netsh int tcp set supplemental template=custom congestionprovider=ctcp
                
                Write-Host "Applied optimal settings for $interfaceName" -ForegroundColor Green
            }
            
            # 9. DNS optimization
            Write-Host "`nWould you like to optimize DNS settings? Choose an option:" -ForegroundColor Yellow
            Write-Host "1. Google DNS (8.8.8.8, 8.8.4.4)" -ForegroundColor White
            Write-Host "2. Cloudflare DNS (1.1.1.1, 1.0.0.1)" -ForegroundColor White
            Write-Host "3. OpenDNS (208.67.222.222, 208.67.220.220)" -ForegroundColor White
            Write-Host "4. Keep current DNS settings" -ForegroundColor White
            
            $dnsChoice = Read-Host "Enter your choice (1-4)"
            
            if ($dnsChoice -ne "4") {
                $dnsPrimary = ""
                $dnsSecondary = ""
                
                switch ($dnsChoice) {
                    "1" { 
                        $dnsPrimary = "8.8.8.8"
                        $dnsSecondary = "8.8.4.4"
                        $dnsProvider = "Google DNS"
                    }
                    "2" { 
                        $dnsPrimary = "1.1.1.1"
                        $dnsSecondary = "1.0.0.1"
                        $dnsProvider = "Cloudflare DNS"
                    }
                    "3" { 
                        $dnsPrimary = "208.67.222.222"
                        $dnsSecondary = "208.67.220.220"
                        $dnsProvider = "OpenDNS"
                    }
                    default {
                        Write-Host "Invalid choice. Keeping current DNS settings." -ForegroundColor Yellow
                        $dnsChoice = "4"
                    }
                }
                
                if ($dnsChoice -ne "4") {
                    foreach ($interface in $connections) {
                        Set-DnsClientServerAddress -InterfaceIndex $interface.ifIndex -ServerAddresses ($dnsPrimary, $dnsSecondary)
                    }
                    Log-Message "Set DNS to $dnsProvider" -logLevel Info -change
                    Write-Host "Set DNS to $dnsProvider" -ForegroundColor Green
                }
            } else {
                Write-Host "Keeping current DNS settings." -ForegroundColor Yellow
            }
            
            # 10. Flush DNS cache
            Write-Host "`nFlushing DNS cache..." -ForegroundColor White
            ipconfig /flushdns
            
            # 11. Register DNS
            Write-Host "Registering DNS..." -ForegroundColor White
            ipconfig /registerdns
            
            # Enable network optimizations
            Write-Host "`n✅ Network optimized successfully!" -ForegroundColor Green
            Log-Message "Network settings optimized with TCPOptimizer-like settings" -logLevel Info -change
        } catch {
            Log-Message "Failed to optimize network setting: $($_.Exception.Message)" -logLevel Error -error
            Write-Host "Failed to optimize network setting: $($_.Exception.Message)" -ForegroundColor Red
        }
    } catch {
        Log-Message "Failed to optimize network: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Failed to optimize network!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`nPress any key to return to the main menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}


# Undo Changes Menu
function Show-UndoMenu {
    try {
        Log-Message "Starting undo changes" -logLevel Info
        $windowsVersion = Check-WindowsVersion
        
        Write-Host "Restoring default settings..." -ForegroundColor Magenta
        
        try {
            # Restore Windows Defender
            if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender") {
                reg delete "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f
                Log-Message "Windows Defender restored" -logLevel Info -change
                Write-Host "Windows Defender restored." -ForegroundColor Green
            } else {
                Log-Message "Windows Defender settings not found, nothing to restore" -logLevel Info
                Write-Host "Windows Defender settings not found, nothing to restore." -ForegroundColor Yellow
            }
            
            # Restore power settings
            powercfg /restoredefaultschemes
            Log-Message "Power settings restored" -logLevel Info -change
            Write-Host "Power settings restored." -ForegroundColor Green
            
            # Restore network settings
            netsh int tcp set global autotuninglevel=normal
            netsh int tcp set global congestionprovider=default
            Log-Message "Network settings restored" -logLevel Info -change
            Write-Host "Network settings restored." -ForegroundColor Green
            
            Log-Message "Default settings restored" -logLevel Info
            Write-Host "Default settings restored successfully!" -ForegroundColor Green
        } catch {
            Log-Message "Error while restoring setting: $($_.Exception.Message)" -logLevel Error -error
            Write-Host "Error while restoring setting: $($_.Exception.Message)" -ForegroundColor Red
        }
    } catch {
        Log-Message "Failed to restore default settings: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Failed to restore default settings!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "Press any key to return to the main menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Support Information
# Support Information
function Show-SupportInfo {
    Clear-Host
    Write-Host "=====================================" -ForegroundColor Red
    Write-Host "          SUPPORT INFORMATION        " -ForegroundColor White
    Write-Host "=====================================" -ForegroundColor Red
    Write-Host "`nIf you encountered any issues or need further assistance," -ForegroundColor Yellow
    Write-Host "please contact the developer at:" -ForegroundColor Yellow
    Write-Host "`nEmail: robert.sullivan1250@gmail.com" -ForegroundColor Cyan
    Write-Host "`nPlease include:" -ForegroundColor Yellow
    Write-Host "- Error messages (if any)" -ForegroundColor White
    Write-Host "- Relevant logs from the Logs folder" -ForegroundColor White
    Write-Host "- Your Windows version" -ForegroundColor White
    Write-Host "- Description of the issue" -ForegroundColor White
    Write-Host "`nThank you for using the Windows Debloater Tool!" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Red
    Write-Host "`nPress any key to return to the main menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}


function Remove-SystemBloat {
    try {
        Log-Message "Starting system debloating and cleanup process" -logLevel Info

        Write-Host "`n🧹 SYSTEM DEBLOATING AND CLEANUP 🧹" -ForegroundColor Cyan
        Write-Host "This will perform system cleanup and remove unnecessary components." -ForegroundColor Yellow
        Write-Host "⚠️ WARNING: This process cannot be easily undone!" -ForegroundColor Red
        
        $confirm = Read-Host "Do you want to proceed? (Y/N)"
        if ($confirm -notmatch "^[Yy]$") {
            Log-Message "System cleanup cancelled by user" -logLevel Info
            return
        }

        # 1. Disable UpdateOrchestrator and Other Tasks
        Write-Host "`nDisabling unnecessary scheduled tasks..." -ForegroundColor Yellow
        $tasksToDisable = @(
            "\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
            "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
            "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
            "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
            "\Microsoft\Windows\UpdateOrchestrator\Schedule Work",
            "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work",
            "\Microsoft\Windows\UpdateOrchestrator\Report policies",
            "\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted",
            "\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate",
            "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
            "\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task",
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Autochk\Proxy",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
            "\Microsoft\Windows\Maintenance\WinSAT",
            "\Microsoft\Windows\PushToInstall\LoginCheck",
            "\Microsoft\Windows\Diagnosis\Scheduled",
            "\Microsoft\Windows\OneDrive\Scheduled",
            "\Microsoft\Windows\OneDrive\StandaloneUpdater"
        )
        foreach ($task in $tasksToDisable) {
            try {
                schtasks /Change /TN $task /Disable
                Log-Message "Disabled task: $task" -logLevel Info -change
            } catch {
                Log-Message "Failed to disable task $task : $($_.Exception.Message)" -logLevel Error -error
            }
        }

        # 2. System Cleanup
        Write-Host "`nPerforming system cleanup..." -ForegroundColor Yellow

        # Temporary files cleanup
        $tempFolders = @(
            "$env:TEMP",
            "$env:SystemRoot\Temp",
            "$env:SystemRoot\Prefetch",
            "$env:SystemRoot\SoftwareDistribution\Download",
            "$env:LOCALAPPDATA\Temp",
            "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
            "$env:LOCALAPPDATA\Microsoft\Windows\WER",
            "$env:SystemRoot\LiveKernelReports",
            "$env:SystemRoot\Memory.dmp",
            "$env:SystemRoot\Minidump"
        )

        foreach ($folder in $tempFolders) {
            try {
                if (Test-Path $folder) {
                    Remove-Item -Path "$folder\*" -Force -Recurse -ErrorAction SilentlyContinue
                    Log-Message "Cleaned folder: $folder" -logLevel Info -change
                }
            } catch {
                Log-Message "Failed to clean folder $folder : $($_.Exception.Message)" -logLevel Error -error
            }
        }

        # 3. Disk Cleanup (cleanmgr)
        Write-Host "`nRunning Disk Cleanup..." -ForegroundColor Yellow
        try {
            Start-Process -FilePath cleanmgr -ArgumentList "/sagerun:1" -Wait
            Log-Message "Disk Cleanup completed" -logLevel Info -change
        } catch {
            Log-Message "Failed to run Disk Cleanup: $($_.Exception.Message)" -logLevel Error -error
        }

        # 4. Clear Event Logs
        Write-Host "`nClearing Event Logs..." -ForegroundColor Yellow
        try {
            wevtutil el | Foreach-Object {wevtutil cl "$_"}
            Log-Message "Event logs cleared" -logLevel Info -change
        } catch {
            Log-Message "Failed to clear event logs: $($_.Exception.Message)" -logLevel Error -error
        }

        # 5. Clear DNS Cache
        Write-Host "`nClearing DNS Cache..." -ForegroundColor Yellow
        try {
            ipconfig /flushdns
            Log-Message "DNS cache cleared" -logLevel Info -change
        } catch {
            Log-Message "Failed to clear DNS cache: $($_.Exception.Message)" -logLevel Error -error
        }

        # 6. Clear Windows Store Cache
        Write-Host "`nClearing Windows Store Cache..." -ForegroundColor Yellow
        try {
            Stop-Process -Name "WindowsStore" -Force -ErrorAction SilentlyContinue
            Set-Location "$env:LOCALAPPDATA\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache"
            Remove-Item * -Recurse -Force -ErrorAction SilentlyContinue
            Log-Message "Windows Store cache cleared" -logLevel Info -change
        } catch {
            Log-Message "Failed to clear Windows Store cache: $($_.Exception.Message)" -logLevel Error -error
        }

        # 7. Clear Thumbnail Cache
        Write-Host "`nClearing Thumbnail Cache..." -ForegroundColor Yellow
        try {
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force
            Log-Message "Thumbnail cache cleared" -logLevel Info -change
        } catch {
            Log-Message "Failed to clear thumbnail cache: $($_.Exception.Message)" -logLevel Error -error
        }

        # 8. Clear Recent Items
        Write-Host "`nClearing Recent Items..." -ForegroundColor Yellow
        try {
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse
            Log-Message "Recent items cleared" -logLevel Info -change
        } catch {
            Log-Message "Failed to clear recent items: $($_.Exception.Message)" -logLevel Error -error
        }

        # 9. Disable Unnecessary Services
        Write-Host "`nDisabling unnecessary services..." -ForegroundColor Yellow
        $servicesToDisable = @(
            "DiagTrack",
            "RetailDemo",
            "SharedAccess",
            "lfsvc",
            "WpcMonSvc",
            "SessionEnv",
            "MicrosoftEdgeElevationService",
            "edgeupdate",
            "edgeupdatem",
            "autotimesvc",
            "CscService",
            "TermService",
            "SensorDataService",
            "SensorService",
            "SensrSvc",
            "shpamsvc",
            "diagnosticshub.standardcollector.service",
            "PhoneSvc",
            "TapiSrv",
            "UevAgentService",
            "WalletService",
            "TokenBroker",
            "WebClient",
            "MixedRealityOpenXRSvc",
            "stisvc",
            "WbioSrvc",
            "icssvc",
            "Wecsvc",
            "SEMgrSvc",
            "iphlpsvc",
            "BthAvctpSvc"
        )
        foreach ($service in $servicesToDisable) {
            try {
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Log-Message "Disabled service: $service" -logLevel Info -change
            } catch {
                Log-Message "Failed to disable service $service : $($_.Exception.Message)" -logLevel Error -error
            }
        }

        Write-Host "`n✅ System cleanup and debloating completed successfully!" -ForegroundColor Green
        Log-Message "System cleanup and debloating completed" -logLevel Info

        # 10. Remove Windows Widgets
    Write-Host "`nRemoving Windows Widgets..." -ForegroundColor Yellow
    try {
    # Stop Widget-related processes
    $widgetProcesses = @("Widgets", "WidgetService", "Windows.WebExperience")
    foreach ($process in $widgetProcesses) {
        Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    
    # Remove Widget packages
    $widgetPackages = @(
        "MicrosoftWindows.Client.WebExperience",
        "Windows.WebExperience",
        "Microsoft.WebExperience"
    )
    foreach ($package in $widgetPackages) {
        Get-AppxPackage -Name $package -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$package*" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    
    # Disable Widget-related services
    $widgetServices = @(
        "TabletInputService",
        "WpnService",
        "WebExperience",
        "WidgetService"
    )
    foreach ($service in $widgetServices) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
    
    # Remove Widget registry keys
    $widgetsKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarMn",
        "HKLM:\SOFTWARE\Policies\Microsoft\Dsh",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
        "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
    )
    
    foreach ($key in $widgetsKeys) {
        if (Test-Path $key) {
            Remove-Item -Path $key -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
    
    # Disable Widgets through Group Policy and Registry
    $registryPaths = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" = @{
            "EnableFeeds" = 0
            "ShellFeedsTaskbarViewMode" = 2
        }
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
            "TaskbarDa" = 0
            "ShowNewsAndInterests" = 0
        }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
            "TaskbarDa" = 0
            "ShowNewsAndInterests" = 0
        }
    }

    foreach ($path in $registryPaths.Keys) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        foreach ($name in $registryPaths[$path].Keys) {
            Set-ItemProperty -Path $path -Name $name -Value $registryPaths[$path][$name] -Type DWord -Force
        }
    }

    # Additional cleanup for WebExperience
    $webExperiencePath = "$env:LOCALAPPDATA\Packages\MicrosoftWindows.Client.WebExperience_*"
    if (Test-Path $webExperiencePath) {
        Remove-Item -Path $webExperiencePath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Log-Message "Windows Widgets removed and disabled" -logLevel Info -change
    Write-Host "Windows Widgets removed and disabled successfully!" -ForegroundColor Green
}
catch {
    Log-Message "Failed to remove Windows Widgets: $($_.Exception.Message)" -logLevel Error -error
    Write-Host "Failed to remove Windows Widgets!" -ForegroundColor Red
}

# Add the Copilot removal RIGHT HERE, after the Widgets section:
Write-Host "`nRemoving Windows Copilot..." -ForegroundColor Yellow
try {
    # Remove Copilot package
    Get-AppxPackage *Windows.Copilot* -AllUsers | Remove-AppxPackage -AllUsers
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Windows.Copilot*" } | Remove-AppxProvisionedPackage -Online
    
    # Disable Copilot through Registry
    $registryPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsCopilot"
    )

    foreach ($path in $registryPaths) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
    }

    # Disable Copilot in various registry locations
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsCopilot" -Name "value" -Value 0 -Type DWord -Force

    # Remove Copilot button from taskbar
    $taskbarSettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction SilentlyContinue
    if ($taskbarSettings) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type DWord -Force
    }

    # Disable Copilot services
    $services = @(
        "CopilotService",
        "WindowsCopilotService"
    )
    foreach ($service in $services) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

    # Block Copilot in Windows Firewall
    $copilotRules = @(
        "Windows Copilot",
        "Microsoft Copilot",
        "Copilot in Windows"
    )
    foreach ($rule in $copilotRules) {
        New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Program "%SystemRoot%\SystemApps\Microsoft.Windows.CopilotUI_*\CopilotUI.exe" -ErrorAction SilentlyContinue
    }

    # Group Policy settings (if available)
    $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    if (!(Test-Path $gpoPath)) {
        New-Item -Path $gpoPath -Force | Out-Null
    }
    Set-ItemProperty -Path $gpoPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force

    Log-Message "Windows Copilot removed and disabled" -logLevel Info -change
    Write-Host "Windows Copilot removed and disabled successfully!" -ForegroundColor Green
}
catch {
    Log-Message "Failed to remove Windows Copilot: $($_.Exception.Message)" -logLevel Error -error
    Write-Host "Failed to remove Windows Copilot!" -ForegroundColor Red
}

Write-Host "`nSystem debloating completed successfully!" -ForegroundColor Green
        Log-Message "System debloating completed" -logLevel Info
    }
    catch {
        Log-Message "Error during system debloating: $($_.Exception.Message)" -logLevel Error -error
        Write-Host "Error during system debloating!" -ForegroundColor Red
    }
}



function Show-MainMenu {
    try {
        $windowsVersion = Check-WindowsVersion
        Create-RestorePoint
        
        while ($true) {
            Clear-Host
            Write-Host "=====================================" -ForegroundColor Red
            Write-Host "       Windows Debloater Tool        " -ForegroundColor White
            Write-Host "=====================================" -ForegroundColor Red
            Write-Host "Detected OS: $windowsVersion" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "1. Remove Bloatware Apps" -ForegroundColor Green
            Write-Host "2. Optimize CPU & GPU" -ForegroundColor Magenta
            Write-Host "3. Optimize Network" -ForegroundColor Blue
            Write-Host "4. Disable Windows Defender" -ForegroundColor Red
            Write-Host "5. System Debloating" -ForegroundColor Green
            Write-Host "6. Undo Changes" -ForegroundColor Magenta
            Write-Host "7. Support Information" -ForegroundColor Yellow
            Write-Host "8. Exit" -ForegroundColor Red
            Write-Host ""
            
            $choice = Read-Host "Please select an option (1-8)"
            
            switch ($choice) {
                "1" { Remove-Apps }
                "2" { Optimize-CPU-GPU }
                "3" { Optimize-Network }
                "4" { Remove-WindowsDefender }
                "5" { Remove-SystemBloat }
                "6" { Show-UndoMenu }
                "7" { Show-SupportInfo }
                "8" { 
                    Clear-Host
                    Write-Host "`n=====================================" -ForegroundColor Red
                    Write-Host "      Windows Debloater Tool          " -ForegroundColor White
                    Write-Host "=====================================" -ForegroundColor Red
                    Write-Host "`nThank you for using Windows Debloater Tool!" -ForegroundColor Green
                    Write-Host "`nThis Program was Developed by Robert 'BobbyBoy' Sullivan" -ForegroundColor Blue 
                    Write-Host "`nIdeas or improvements? Contact me:" -ForegroundColor Yellow
                    Write-Host "robert.sullivan1250@gmail.com" -ForegroundColor Yellow
                    Write-Host "`n=====================================" -ForegroundColor Red
                    Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    exit 
                }

                default { 
                    Write-Host "`nInvalid choice. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                }
            }
        }
    } catch {
        Log-Message "Error in main menu: $($_.Exception.Message)" -logLevel Error -error
        Show-SupportInfo
        Show-MainMenu
    }
}


# Ensure we're running as admin
Ensure-Admin

# Debug Windows version detection
$winVer = [System.Environment]::OSVersion.Version
Write-Host "Debug - Windows Version: Major=$($winVer.Major), Minor=$($winVer.Minor), Build=$($winVer.Build)" -ForegroundColor Yellow

# Start the script
Show-MainMenu




# Disable unnecessary scheduled tasks
$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
    "\Microsoft\Windows\Maintenance\WinSAT",
    "\Microsoft\Windows\PushToInstall\LoginCheck",
    "\Microsoft\Windows\Diagnosis\Scheduled",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\OneDrive\Scheduled",
    "\Microsoft\Windows\OneDrive\StandaloneUpdater",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Work",
    "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work",
    "\Microsoft\Windows\UpdateOrchestrator\Report policies",
    "\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted",
    "\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate",
    "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
    "\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"  # Removed trailing comma
)


foreach ($task in $tasks) {
    if (Get-ScheduledTask -TaskPath $task -ErrorAction SilentlyContinue) {
        Disable-ScheduledTask -TaskPath $task -ErrorAction SilentlyContinue
        Write-Host "Disabled: $task"
    } else {
        Write-Host "Task not found: $task"
    }
}
