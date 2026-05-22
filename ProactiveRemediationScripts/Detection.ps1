#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Detection script for Intune Proactive Remediation to identify machines with stale user profiles.

.DESCRIPTION
    Reads tracked user profiles from HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon (written by the
    TrueLogon Tracker at install and updated on every interactive logon by the
    scheduled task). Triggers remediation if at least one profile's LastLogon
    is older than the age threshold, regardless of how many profiles are on
    the device.

    Both this script and Remediation.ps1 read the same source of truth so
    they can't disagree about who is stale. If the TrueLogon Tracker is not
    installed on the device, this script exits 0 (compliant) - Remediation
    would have nothing to act on either.

.PARAMETER DaysThreshold
    Number of days since last logon to consider a profile "stale". Default is 90.

.EXAMPLE
    .\Detection.ps1
    Runs detection with default 90 days age threshold.

.EXAMPLE
    .\Detection.ps1 -DaysThreshold 60
    Runs detection with custom 60 days age threshold.

.NOTES
    Author:  Joshua Walderbach
    Version: 1.0.8
    Created: 2025-11-18
    Updated: 2026-05-22
    Exit 0:  Compliant (no stale profiles, or TrueLogon not installed)
    Exit 1:  Non-compliant (one or more stale profiles, triggers remediation)
    Exit 2:  Critical error during detection
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$DaysThreshold = 90
)

# Force 64-bit on a 64-bit OS. Intune's IME can launch Proactive Remediation
# detections under WOW64, in which case every read of HKLM:\SOFTWARE\Walmart\...
# is silently redirected to WOW6432Node and we'd miss the Tracker's data.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $Relaunch = Join-Path -Path $env:SystemRoot -ChildPath 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    & $Relaunch -ExecutionPolicy Bypass -NoProfile -File $PSCommandPath -DaysThreshold $DaysThreshold
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'

# Keep $Script:RegistryPath named identically in every script that touches it
# (Tracker/Install.ps1, embedded tracker, Tracker/Detection.ps1, PR/Detection.ps1,
# PR/Remediation.ps1) so a future rename is grep-able across the repo.
$Script:RegistryPath = "HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon"

# Configuration
$Script:Config = @{
    DaysThreshold  = $DaysThreshold
    LogDirectory   = "C:\ProgramData\TrueLogon\Logs"
    LogFileName    = "TrueLogon-ProfileDetection.log"
    MaxLogSizeMB   = 5
}

#region Logging Function
function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes log messages in CMTrace format with automatic log rotation.
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
        [string]$Component = 'ProfileDetection'
    )

    begin {
        $LogPath = $Script:Config.LogDirectory
        $LogFileName = $Script:Config.LogFileName
        $MaxFileSizeMB = $Script:Config.MaxLogSizeMB
        $LogFile = Join-Path -Path $LogPath -ChildPath $LogFileName

        # Ensure the directory exists
        if (-not (Test-Path -Path $LogPath)) {
            try {
                New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
            }
            catch {
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
                    # Continue with existing file if rotation fails
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
            $UtcOffset = [System.TimeZoneInfo]::Local.GetUtcOffset($Now).TotalMinutes

            # Build CMTrace log entry
            $LogEntry = "<![LOG[$Message]LOG]!><time=`"$Time+$UtcOffset`" date=`"$Date`" component=`"$Component`" context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" type=`"$Type`" thread=`"$PID`" file=`"Detection.ps1`">"

            # Write the log entry
            Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {
            # Silently continue if logging fails
        }
    }
}
#endregion Logging Function

Write-LogMessage -Message "Starting profile detection (age threshold: $($Script:Config.DaysThreshold) days)" -Level Information

try {
    # Read TrueLogon registry (written by the Tracker). If it doesn't exist,
    # the Tracker isn't deployed - exit compliant rather than error, because
    # Remediation would have nothing to act on either.
    if (-not (Test-Path $Script:RegistryPath)) {
        Write-LogMessage -Message "TrueLogon registry path not found: $($Script:RegistryPath). Tracker is not installed - exiting compliant." -Level Warning
        Write-Output "Compliant: TrueLogon Tracker is not installed on this device"
        exit 0
    }

    # Only S-1-5-21-* children represent real users. The installer's orphan-SID
    # cleanup already removes S-1-5-18/19/20 keys, but filter defensively.
    $allEntries = Get-ChildItem -Path $Script:RegistryPath -ErrorAction Stop |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' }

    $profileCount = $allEntries.Count
    $ageThresholdDate = (Get-Date).AddDays(-$Script:Config.DaysThreshold)

    Write-LogMessage -Message "Found $profileCount tracked user profiles. Checking for any older than $($Script:Config.DaysThreshold) days..." -Level Information

    # Single gate: any profile older than the age threshold triggers remediation,
    # regardless of total profile count. Remediation has its own safety filters
    # (skip loaded profiles, require a matching Win32_UserProfile, honor the
    # exclusion list) to prevent collateral damage.
    $staleProfiles = @()
    foreach ($entry in $allEntries) {
        $entryData = Get-ItemProperty -Path $entry.PSPath -ErrorAction SilentlyContinue
        $lastLogonStr = $entryData.LastLogon
        $username     = $entryData.Username

        if (-not $lastLogonStr) {
            Write-LogMessage -Message "Skipping SID '$($entry.PSChildName)' (user '$username'): LastLogon value missing - corrupt or partial entry" -Level Warning
            continue
        }

        try {
            # Strict parse - LastLogon must always be written by the tracker in
            # exactly this format. If a future change drifts the format, both
            # this script and Remediation.ps1 will throw immediately, which is
            # the desired loud failure.
            $lastLogon = [DateTime]::ParseExact($lastLogonStr, 'yyyy-MM-ddTHH:mm:ss', $null)
        }
        catch {
            Write-LogMessage -Message "Skipping SID '$($entry.PSChildName)' (user '$username'): cannot parse LastLogon value '$lastLogonStr': $($_.Exception.Message)" -Level Warning
            continue
        }

        if ($lastLogon -lt $ageThresholdDate) {
            $daysOld = [math]::Round(((Get-Date) - $lastLogon).TotalDays)
            $staleProfiles += @{
                SID       = $entry.PSChildName
                Username  = $username
                LastLogon = $lastLogon
                DaysOld   = $daysOld
            }
            Write-LogMessage -Message "Stale profile found: '$username' (SID $($entry.PSChildName)) LastLogon=$($lastLogon.ToString('yyyy-MM-dd')) ($daysOld days ago)" -Level Information
        }
    }

    if ($staleProfiles.Count -gt 0) {
        Write-LogMessage -Message "NON-COMPLIANT: Found $($staleProfiles.Count) profile(s) older than $($Script:Config.DaysThreshold) days (of $profileCount total tracked)" -Level Warning
        Write-Output "Non-compliant: $($staleProfiles.Count) stale profile(s) found (>$($Script:Config.DaysThreshold) days)"
        exit 1  # Non-compliant, trigger remediation
    }
    else {
        Write-LogMessage -Message "COMPLIANT: No profiles older than $($Script:Config.DaysThreshold) days (of $profileCount total tracked)" -Level Information
        Write-Output "Compliant: No stale profiles found (>$($Script:Config.DaysThreshold) days)"
        exit 0
    }
}
catch {
    Write-LogMessage -Message "Critical error reading TrueLogon registry: $($_.Exception.Message)" -Level Error
    Write-Output "ERROR: Failed to read TrueLogon registry - $($_.Exception.Message)"
    exit 2
}
