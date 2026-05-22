#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Identifies and removes stale user profiles based on TrueLogon data.

.DESCRIPTION
    This script analyzes the True Logon registry data to identify user profiles
    that haven't logged in within a specified threshold. It logs profile information
    (username, last logon, disk usage) and removes the user account, profile directory,
    and registry entry.

.PARAMETER DaysThreshold
    Number of days of inactivity before a profile is considered stale. Default is 90 days.

.PARAMETER WhatIf
    Runs the script in simulation mode without actually deleting profiles. Shows what would be deleted.

.PARAMETER ExcludeUsers
    Array of usernames to exclude from cleanup (in addition to default exclusions).

.EXAMPLE
    .\Remediation.ps1 -DaysThreshold 180
    Removes profiles inactive for 180+ days.

.EXAMPLE
    .\Remediation.ps1 -DaysThreshold 90 -WhatIf
    Simulates cleanup of 90+ day inactive profiles without deleting.

.NOTES
    Author: Joshua Walderbach
    Version: 1.0.5
    Updated: 2026-05-18
    Requires: Administrator privileges
    Log Path: C:\ProgramData\TrueLogon\Logs\TrueLogon-Remediation.log
    Exit 0:  Clean run (all targeted profiles removed successfully)
    Exit 1:  Partial failure (one or more profiles could not be removed)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$DaysThreshold = 90,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeUsers = @()
)

# ===================================================================================================
# CONFIGURATION
# ===================================================================================================

$Script:Version = '1.0.5'

# Users to never track or clean up. Must match $Script:DefaultExcludeUsers
# in Tracker/Install.ps1 exactly.
$Script:DefaultExcludeUsers = @("Default", "Default User", "Public", "All Users", "Administrator", "Moonpie")

# Keep $Script:RegistryPath named identically in every script that touches it
# (Tracker/Install.ps1, embedded tracker, Tracker/Detection.ps1, PR/Detection.ps1,
# PR/Remediation.ps1) so a future rename is grep-able across the repo.
$Script:RegistryPath = "HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon"

$Script:Config = @{
    LogDirectory      = "C:\ProgramData\TrueLogon\Logs"
    LogFileName       = "TrueLogon-Remediation.log"
    MaxLogSizeBytes   = 5MB
    DefaultExclusions = $Script:DefaultExcludeUsers
}

# ===================================================================================================
# LOGGING FUNCTIONS
# ===================================================================================================

function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes log messages in CMTrace format with automatic log rotation.

    .DESCRIPTION
        Logs messages to a specified file in CMTrace format, compatible with CMTrace.exe and OneTrace.
        Supports automatic log file rotation when size threshold is exceeded.

    .PARAMETER Message
        The message to be logged.

    .PARAMETER Level
        The severity level: Verbose, Warning, Error, Information, Debug.
        Default: Information

    .PARAMETER Component
        The component or script name generating the log entry.
        Default: 'Remediation'

    .NOTES
        CMTrace format enables viewing with CMTrace.exe/OneTrace with color-coded severity.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('Verbose', 'Warning', 'Error', 'Information', 'Debug')]
        [string]$Level = 'Information',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Component = 'Remediation'
    )

    begin {
        $LogPath = $Script:Config.LogDirectory
        $LogFileName = $Script:Config.LogFileName
        $MaxFileSizeMB = $Script:Config.MaxLogSizeBytes / 1MB
        $LogFile = Join-Path -Path $LogPath -ChildPath $LogFileName

        # Ensure the directory exists
        if (-not (Test-Path -Path $LogPath)) {
            try {
                New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
            }
            catch {
                Write-Warning "Failed to create log directory at '$LogPath': $($_.Exception.Message)"
                return
            }
        }

        # Check if the log file exists and its size - rotate if needed
        if (Test-Path -Path $LogFile) {
            $FileSizeMB = (Get-Item -Path $LogFile).Length / 1MB
            if ($FileSizeMB -ge $MaxFileSizeMB) {
                $Timestamp = Get-Date -Format "yyyyMMddHHmmss"
                $ArchivedLog = "$LogFile.$Timestamp.bak"
                try {
                    Rename-Item -Path $LogFile -NewName $ArchivedLog -ErrorAction Stop
                }
                catch {
                    Write-Warning "Log rotation failed for '$LogFile'. Continuing with existing file."
                }
            }
        }
    }

    process {
        try {
            # Map level to CMTrace type: 1=Info, 2=Warning, 3=Error
            $Type = switch ($Level) {
                'Error'   { 3 }
                'Warning' { 2 }
                default   { 1 }
            }

            # Build CMTrace format timestamp
            $Now = Get-Date
            $Time = $Now.ToString("HH:mm:ss.fff")
            $Date = $Now.ToString("MM-dd-yyyy")

            # Get timezone offset
            $UtcOffset = [System.TimeZoneInfo]::Local.GetUtcOffset($Now).TotalMinutes

            # Build CMTrace log entry
            $LogEntry = "<![LOG[$Message]LOG]!><time=`"$Time+$UtcOffset`" date=`"$Date`" component=`"$Component`" context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" type=`"$Type`" thread=`"$PID`" file=`"Remediation.ps1`">"

            # Write the log entry
            Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8 -ErrorAction Stop

            # Output to console based on log level
            switch ($Level) {
                'Verbose'     { if ($VerbosePreference -ne 'SilentlyContinue') { Write-Verbose -Message $Message } }
                'Warning'     { Write-Warning -Message $Message }
                'Error'       { Write-Error -Message $Message }
                'Information' { Write-Information -MessageData $Message -InformationAction Continue }
                'Debug'       { if ($DebugPreference -ne 'SilentlyContinue') { Write-Debug -Message $Message } }
            }
        }
        catch {
            Write-Warning "Failed to write log entry: $($_.Exception.Message)"
        }
    }
}

# ===================================================================================================
# HELPER FUNCTIONS
# ===================================================================================================

function Get-ProfileDiskUsage {
    <#
    .SYNOPSIS
        Calculates the disk space used by a user profile directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath
    )

    try {
        if (-not (Test-Path -Path $ProfilePath)) {
            return 0
        }

        $totalSize = 0
        Get-ChildItem -Path $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object { $totalSize += $_.Length }

        return $totalSize
    }
    catch {
        Write-LogMessage -Message "Failed to calculate disk usage for profile '$ProfilePath': $_" -Level Warning
        return 0
    }
}

function Format-FileSize {
    <#
    .SYNOPSIS
        Formats bytes into human-readable size (KB, MB, GB).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )

    if ($Bytes -ge 1GB) {
        return "{0:N2} GB" -f ($Bytes / 1GB)
    }
    elseif ($Bytes -ge 1MB) {
        return "{0:N2} MB" -f ($Bytes / 1MB)
    }
    elseif ($Bytes -ge 1KB) {
        return "{0:N2} KB" -f ($Bytes / 1KB)
    }
    else {
        return "$Bytes Bytes"
    }
}

function Remove-UserProfileSafely {
    <#
    .SYNOPSIS
        Safely removes a user profile, account, and registry entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $true)]
        [string]$SID,

        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )

    $errors = @()
    $successOperations = @()

    # 1. Remove local user account
    try {
        $localUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
        if ($localUser) {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove local user account: $Username" -Level Information
                $successOperations += "User account (simulated)"
            }
            else {
                Remove-LocalUser -Name $Username -ErrorAction Stop
                Write-LogMessage -Message "Successfully removed local user account: $Username" -Level Information
                $successOperations += "User account"
            }
        }
        else {
            Write-LogMessage -Message "Local user account not found (may be domain account): $Username" -Level Information
        }
    }
    catch {
        $errorMsg = "Failed to remove user account '$Username': $_"
        Write-LogMessage -Message $errorMsg -Level Warning
        $errors += $errorMsg
    }

    # 2. Remove user profile using CIM
    try {
        $userProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $SID }

        if ($userProfile) {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove user profile via CIM: $ProfilePath" -Level Information
                $successOperations += "User profile (simulated)"
            }
            else {
                Remove-CimInstance -InputObject $userProfile -ErrorAction Stop
                Write-LogMessage -Message "Successfully removed user profile via CIM: $ProfilePath" -Level Information
                $successOperations += "User profile"
            }
        }
        else {
            Write-LogMessage -Message "User profile not found in Win32_UserProfile: $ProfilePath" -Level Warning
        }
    }
    catch {
        $errorMsg = "Failed to remove user profile via CIM '$ProfilePath': $_"
        Write-LogMessage -Message $errorMsg -Level Warning
        $errors += $errorMsg

        # Fallback: Try manual directory deletion
        try {
            if (Test-Path -Path $ProfilePath) {
                if ($WhatIf) {
                    Write-LogMessage -Message "[WHATIF] Would manually remove profile directory: $ProfilePath" -Level Information
                }
                else {
                    Remove-Item -Path $ProfilePath -Recurse -Force -ErrorAction Stop
                    Write-LogMessage -Message "Successfully removed profile directory manually: $ProfilePath" -Level Information
                    $successOperations += "Profile directory (manual)"
                }
            }
        }
        catch {
            $errorMsg = "Failed to manually remove profile directory '$ProfilePath': $_"
            Write-LogMessage -Message $errorMsg -Level Error
            $errors += $errorMsg
        }
    }

    # 3. Remove registry entry from TrueLogon
    try {
        $sidKeyPath = Join-Path -Path $Script:RegistryPath -ChildPath $SID
        if (Test-Path -Path $sidKeyPath) {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove registry entry for SID: $SID" -Level Information
                $successOperations += "Registry entry (simulated)"
            }
            else {
                Remove-Item -Path $sidKeyPath -Recurse -Force -ErrorAction Stop
                Write-LogMessage -Message "Successfully removed registry entry for SID: $SID" -Level Information
                $successOperations += "Registry entry"
            }
        }
    }
    catch {
        $errorMsg = "Failed to remove registry entry for SID '$SID': $_"
        Write-LogMessage -Message $errorMsg -Level Warning
        $errors += $errorMsg
    }

    return @{
        Success = ($errors.Count -eq 0)
        Errors = $errors
        Operations = $successOperations
    }
}

# ===================================================================================================
# MAIN EXECUTION
# ===================================================================================================

function Start-ProfileCleanup {
    [CmdletBinding()]
    param()

    $startTime = Get-Date
    $whatIfText = if ($WhatIf) { " [WHATIF MODE]" } else { "" }

    Write-LogMessage -Message "========== Profile Cleanup Started$whatIfText (Version: $Script:Version, DaysThreshold: $DaysThreshold) ==========" -Level Information

    # Verify registry path exists
    if (-not (Test-Path -Path $Script:RegistryPath)) {
        Write-LogMessage -Message "True Logon registry path not found: $($Script:RegistryPath)" -Level Error
        Write-Host "ERROR: True Logon registry path not found. Ensure the tracking system is installed." -ForegroundColor Red
        exit 1
    }

    # Build complete exclusion list
    $allExclusions = $Script:Config.DefaultExclusions + $ExcludeUsers | Select-Object -Unique

    # Get current date for comparison
    $currentDate = Get-Date
    $thresholdDate = $currentDate.AddDays(-$DaysThreshold)

    Write-Host "`nScanning for profiles inactive since: $($thresholdDate.ToString('yyyy-MM-dd HH:mm:ss'))$whatIfText" -ForegroundColor Cyan
    Write-Host "Threshold: $DaysThreshold days`n" -ForegroundColor Cyan

    # Get all registry entries
    try {
        $registryEntries = Get-ChildItem -Path $Script:RegistryPath -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' }
    }
    catch {
        Write-LogMessage -Message "Failed to read registry data: $_" -Level Error
        Write-Host "ERROR: Failed to read registry data: $_" -ForegroundColor Red
        exit 1
    }

    # Get all user profiles
    $allProfiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special }

    # Process each user in registry
    $staleProfiles = @()
    $totalSpaceReclaimed = 0
    $processedCount = 0
    $RemediationErrors = 0

    foreach ($registryEntry in $registryEntries) {
        $sid = $registryEntry.PSChildName
        $entryData = Get-ItemProperty -Path $registryEntry.PSPath -ErrorAction SilentlyContinue
        $username = $entryData.Username
        $displayName = if ($username) { $username } else { $sid }

        # Skip excluded users
        if ($username -and ($allExclusions -contains $username)) {
            Write-LogMessage -Message "Skipping excluded user: $username" -Level Verbose
            continue
        }

        $lastLogonString = $entryData.LastLogon
        $processedCount++

        try {
            if (-not $lastLogonString) {
                Write-LogMessage -Message "Missing LastLogon value for SID '$sid' (user '$displayName')" -Level Warning
                Write-Host "Missing LastLogon for SID $sid ($displayName)" -ForegroundColor Yellow
                continue
            }

            # Parse last logon date
            $lastLogonDate = [DateTime]::ParseExact($lastLogonString, 'yyyy-MM-ddTHH:mm:ss', $null)

            # Check if profile is stale
            if ($lastLogonDate -lt $thresholdDate) {
                $daysSinceLogon = [math]::Round(($currentDate - $lastLogonDate).TotalDays, 1)

                # Find matching profile
                $matchingProfile = $allProfiles | Where-Object { $_.SID -eq $sid }

                if (-not $matchingProfile) {
                    Write-LogMessage -Message "No matching profile found for SID '$sid' (user '$displayName')" -Level Warning
                    Write-Host "No matching profile found for SID $sid ($displayName)" -ForegroundColor Yellow
                    continue
                }

                if ($matchingProfile.Loaded) {
                    Write-LogMessage -Message "Skipping loaded profile for user '$displayName' at '$($matchingProfile.LocalPath)'" -Level Warning
                    Write-Host "Skipping loaded profile for $displayName at $($matchingProfile.LocalPath)" -ForegroundColor Yellow
                    continue
                }

                $profilePath = $matchingProfile.LocalPath
                $profileSID = $matchingProfile.SID

                # Calculate disk usage
                $diskUsageBytes = Get-ProfileDiskUsage -ProfilePath $profilePath
                $diskUsageFormatted = Format-FileSize -Bytes $diskUsageBytes

                $profileInfo = [PSCustomObject]@{
                    Username          = $displayName
                    LastLogon         = $lastLogonDate.ToString('yyyy-MM-dd HH:mm:ss')
                    DaysSinceLogon    = $daysSinceLogon
                    ProfilePath       = $profilePath
                    DiskUsageBytes    = $diskUsageBytes
                    DiskUsageFormatted = $diskUsageFormatted
                    SID               = $profileSID
                }

                $staleProfiles += $profileInfo

                # Display profile information
                Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
                Write-Host "Username:       " -NoNewline -ForegroundColor Yellow
                Write-Host $displayName -ForegroundColor White
                Write-Host "Last Logon:     " -NoNewline -ForegroundColor Yellow
                Write-Host $lastLogonDate.ToString('yyyy-MM-dd HH:mm:ss') -ForegroundColor White
                Write-Host "Days Inactive:  " -NoNewline -ForegroundColor Yellow
                Write-Host "$daysSinceLogon days" -ForegroundColor Red
                Write-Host "Profile Path:   " -NoNewline -ForegroundColor Yellow
                Write-Host $profilePath -ForegroundColor White
                Write-Host "Disk Usage:     " -NoNewline -ForegroundColor Yellow
                Write-Host $diskUsageFormatted -ForegroundColor Cyan

                # Log profile details
                Write-LogMessage -Message "Stale profile identified: $displayName (SID: $profileSID, LastLogon: $($lastLogonDate.ToString('yyyy-MM-dd')), Inactive: $daysSinceLogon days, Size: $diskUsageFormatted)" -Level Information

                # Delete profile
                if ($WhatIf) {
                    Write-Host "Action:         " -NoNewline -ForegroundColor Yellow
                    Write-Host "[SIMULATION] Would delete profile" -ForegroundColor Magenta
                }
                else {
                    Write-Host "Action:         " -NoNewline -ForegroundColor Yellow
                    Write-Host "Deleting profile..." -ForegroundColor Red
                }

                $result = Remove-UserProfileSafely -Username $displayName -ProfilePath $profilePath -SID $profileSID -WhatIf:$WhatIf

                if ($result.Success) {
                    $totalSpaceReclaimed += $diskUsageBytes
                    Write-Host "Status:         " -NoNewline -ForegroundColor Yellow
                    Write-Host "SUCCESS - Removed: $($result.Operations -join ', ')" -ForegroundColor Green
                }
                else {
                    $RemediationErrors++
                    Write-Host "Status:         " -NoNewline -ForegroundColor Yellow
                    Write-Host "PARTIAL - Errors occurred" -ForegroundColor Red
                    foreach ($err in $result.Errors) {
                        Write-Host "  └─ $err" -ForegroundColor Red
                    }
                }
            }
        }
        catch {
            $RemediationErrors++
            Write-LogMessage -Message "Error processing user '$username': $_" -Level Error
            Write-Host "ERROR processing '$username': $_" -ForegroundColor Red
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "CLEANUP SUMMARY$whatIfText" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Total Users Scanned:        $processedCount" -ForegroundColor White
    Write-Host "Stale Profiles Found:       $($staleProfiles.Count)" -ForegroundColor Yellow
    Write-Host "Disk Space Reclaimed:       $(Format-FileSize -Bytes $totalSpaceReclaimed)" -ForegroundColor Cyan
    Write-Host "Removal Failures:           $RemediationErrors" -ForegroundColor $(if ($RemediationErrors -gt 0) { 'Red' } else { 'White' })
    Write-Host "Days Threshold:             $DaysThreshold days" -ForegroundColor White

    $duration = (Get-Date) - $startTime
    Write-Host "Execution Time:             $($duration.ToString('mm\:ss'))" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Green

    Write-LogMessage -Message "========== Profile Cleanup Completed$whatIfText (Scanned: $processedCount, Stale: $($staleProfiles.Count), Reclaimed: $(Format-FileSize -Bytes $totalSpaceReclaimed), Failures: $RemediationErrors) ==========" -Level Information

    if ($RemediationErrors -gt 0) {
        Write-LogMessage -Message "Exiting 1 - $RemediationErrors removal failure(s) occurred. Intune will surface this as a failed remediation." -Level Warning
        exit 1
    }
    exit 0
}

# Execute main function
try {
    Start-ProfileCleanup
}
catch {
    Write-LogMessage -Message "Critical error in profile cleanup: $_" -Level Error
    Write-Host "`nCRITICAL ERROR: $_" -ForegroundColor Red
    exit 1
}
