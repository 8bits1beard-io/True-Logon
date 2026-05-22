#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Detection script for Intune Win32 app detection or manual validation of True Logon installation.

.DESCRIPTION
    Validates that the True Logon system is properly installed and functional by checking
    five required components: scheduled task, script file (with SHA256 integrity check),
    registry path, registry entries, and version marker.

    This script is designed for Intune Win32 app detection or manual validation. When components
    are missing or non-functional, it returns exit code 1.

.NOTES
    Author:  Joshua Walderbach
    Version: 2.0.4
    Created: 2025-11-18
    Updated: 2026-05-22

    Exit Codes:
    - 0: Fully compliant (all 5 components present and functional)
    - 1: Non-compliant
    - 2: Critical error during detection

    Components Validated:
    1. Scheduled Task   - Exists, enabled, and its action executes PowerShell
                          against the expected tracker script
    2. Script File      - Exists at expected path AND its SHA256 matches the value the
                          installer wrote to HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon\ScriptHash
    3. Registry Path    - Base registry key exists
    4. Registry Entries - At least one S-1-5-21-* user entry is present
    5. Version Marker   - HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon\Version equals the expected version
                          baked into this script (drives upgrade redeploys)

.EXAMPLE
    .\Detection.ps1
    Runs detection and outputs compliance status to console (captured by Intune).
#>

[CmdletBinding()]
param()

# Force 64-bit on a 64-bit OS so registry reads see the native hive that
# Install.ps1 writes to. If Intune launches this detection rule under WOW64,
# every HKLM:\SOFTWARE\Walmart\... read would be redirected to WOW6432Node
# and report the install as missing.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $Relaunch = Join-Path -Path $env:SystemRoot -ChildPath 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    & $Relaunch -ExecutionPolicy Bypass -NoProfile -File $PSCommandPath
    exit $LASTEXITCODE
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
        [string]$Component = 'Detection',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPath = "C:\ProgramData\TrueLogon\Logs",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFileName = "TrueLogon-Detection.log",

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100)]
        [int]$MaxFileSizeMB = 5
    )

    begin {
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

# Keep $Script:RegistryPath named identically in every script that touches it
# (Tracker/Install.ps1, embedded tracker, Tracker/Detection.ps1, PR/Detection.ps1,
# PR/Remediation.ps1) so a future rename is grep-able across the repo.
$Script:RegistryPath = "HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon"

# Path to the tracker script on disk. Matches $Script:TrackerScriptPath
# in Tracker/Install.ps1 (each script owns its own copy).
$Script:TrackerScriptPath = 'C:\ProgramData\TrueLogon\TrueLogon.ps1'

# Configuration variables - centralized for easy maintenance
$Script:Config = @{
    TaskName = "TrueLogon"
    # Must match $Script:Version in Tracker/Install.ps1 and the Version field
    # in both script headers. They must match exactly or Detection will mark
    # every install non-compliant and Intune will redeploy.
    ExpectedVersion = "2.0.4"
    RequiredComponents = 5      # Total number of components to validate
}

# Initialize detection results
$DetectionResults = @{
    ScheduledTask = $false
    ScriptFile = $false
    RegistryPath = $false
    RegistryEntries = $false
    VersionMarker = $false
}

$ErrorMessages = @()

Write-LogMessage -Message "Starting True Logon detection script" -Level 'Information'

try {
    # Test 1: Check for scheduled task (existence, enabled state, and action).
    # Uses schtasks.exe /XML instead of Get-ScheduledTask — the cmdlet enumerates
    # every task in the scheduler and routinely takes 45-90s on managed devices,
    # blowing past Intune's 60s detection script timeout.
    try {
        $SchOutput = & schtasks.exe /Query /TN $Script:Config.TaskName /XML 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            $ErrorMessages += "Scheduled task '$($Script:Config.TaskName)' not found (schtasks exit $LASTEXITCODE)"
            Write-LogMessage -Message "Scheduled Task check: FAILED - schtasks.exe exit $LASTEXITCODE`: $($SchOutput.Trim())" -Level 'Error'
        } else {
            # schtasks /XML declares encoding="UTF-16" in the prolog but the bytes
            # PowerShell hands back are already transcoded. Strip the declaration
            # before parsing — leaving it triggers an encoding mismatch in [xml].
            $TaskStart = $SchOutput.IndexOf('<Task')
            if ($TaskStart -lt 0) {
                throw "schtasks.exe did not return a <Task> element: $($SchOutput.Trim())"
            }
            [xml]$TaskXml = $SchOutput.Substring($TaskStart)

            $Enabled = $TaskXml.Task.Settings.Enabled
            $ExecCommand = $TaskXml.Task.Actions.Exec.Command
            $ExecArguments = $TaskXml.Task.Actions.Exec.Arguments

            if ($Enabled -eq 'false') {
                $ErrorMessages += "Scheduled task '$($Script:Config.TaskName)' exists but is disabled"
                Write-LogMessage -Message "Scheduled Task check: FAILED - Task is disabled" -Level 'Warning'
            }
            elseif (-not $ExecCommand) {
                $ErrorMessages += "Scheduled task '$($Script:Config.TaskName)' has no actions"
                Write-LogMessage -Message "Scheduled Task check: FAILED - Task has no actions" -Level 'Error'
            }
            elseif ($ExecCommand -notlike '*PowerShell.exe*') {
                $ErrorMessages += "Scheduled task action does not execute PowerShell.exe: $ExecCommand"
                Write-LogMessage -Message "Scheduled Task check: FAILED - Unexpected Execute: $ExecCommand" -Level 'Error'
            }
            elseif ($ExecArguments -notlike "*$($Script:TrackerScriptPath)*") {
                $ErrorMessages += "Scheduled task action arguments do not reference '$($Script:TrackerScriptPath)': $ExecArguments"
                Write-LogMessage -Message "Scheduled Task check: FAILED - Arguments don't reference expected script" -Level 'Error'
            }
            else {
                $DetectionResults.ScheduledTask = $true
                Write-LogMessage -Message "Scheduled Task check: PASSED - Task is enabled, action points at expected script" -Level 'Information'
            }
        }
    } catch {
        $ErrorMessages += "Error checking scheduled task: $($_.Exception.Message)"
        Write-LogMessage -Message "Scheduled Task check: FAILED - Error: $($_.Exception.Message)" -Level 'Error'
    }

    # Test 2: Check for tracking script file (existence + SHA256 integrity)
    try {
        if (Test-Path $Script:TrackerScriptPath) {
            # Hash-verify against the value the installer wrote to the registry.
            # Pre-2.0.1 installs won't have ScriptHash and will fail this check,
            # which is intended — they need to be redeployed for the SID-bug fix.
            try {
                $ActualHash = (Get-FileHash -Path $Script:TrackerScriptPath -Algorithm SHA256 -ErrorAction Stop).Hash
                $ExpectedHash = (Get-ItemProperty -Path $Script:RegistryPath -Name ScriptHash -ErrorAction SilentlyContinue).ScriptHash

                if (-not $ExpectedHash) {
                    $ErrorMessages += "Script hash missing from registry (pre-2.0.1 install or partial install)"
                    Write-LogMessage -Message "Script File check: FAILED - ScriptHash registry value not present" -Level 'Warning'
                }
                elseif ($ActualHash -ne $ExpectedHash) {
                    $ErrorMessages += "Script hash mismatch: file=$ActualHash registry=$ExpectedHash"
                    Write-LogMessage -Message "Script File check: FAILED - Hash mismatch (file tampered or partially written)" -Level 'Error'
                }
                else {
                    $DetectionResults.ScriptFile = $true
                    Write-LogMessage -Message "Script File check: PASSED - File exists and hash matches registry" -Level 'Information'
                }
            } catch {
                $ErrorMessages += "Could not verify script hash: $($_.Exception.Message)"
                Write-LogMessage -Message "Script File check: FAILED - Hash verification threw: $($_.Exception.Message)" -Level 'Error'
            }
        } else {
            $ErrorMessages += "Script file not found: $($Script:TrackerScriptPath)"
            Write-LogMessage -Message "Script File check: FAILED - File not found at $($Script:TrackerScriptPath)" -Level 'Error'
        }
    } catch {
        $ErrorMessages += "Error checking script file: $($_.Exception.Message)"
        Write-LogMessage -Message "Script File check: FAILED - Error: $($_.Exception.Message)" -Level 'Error'
    }

    # Test 3: Check for registry path
    try {
        if (Test-Path $Script:RegistryPath) {
            $DetectionResults.RegistryPath = $true
            Write-LogMessage -Message "Registry Path check: PASSED - Path exists at $($Script:RegistryPath)" -Level 'Information'
        } else {
            $ErrorMessages += "Registry path not found: $($Script:RegistryPath)"
            Write-LogMessage -Message "Registry Path check: FAILED - Path not found at $($Script:RegistryPath)" -Level 'Error'
        }
    } catch {
        $ErrorMessages += "Error checking registry path: $($_.Exception.Message)"
        Write-LogMessage -Message "Registry Path check: FAILED - Error: $($_.Exception.Message)" -Level 'Error'
    }

    # Test 4: Check for registry entries (user profiles)
    try {
        if ($DetectionResults.RegistryPath) {
            $RegistryEntries = Get-ChildItem -Path $Script:RegistryPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
                Measure-Object

            if ($RegistryEntries.Count -gt 0) {
                $DetectionResults.RegistryEntries = $true
                Write-LogMessage -Message "Registry Entries check: PASSED - Found $($RegistryEntries.Count) user profile entries" -Level 'Information'
            } else {
                $ErrorMessages += "No user profile entries found in registry"
                Write-LogMessage -Message "Registry Entries check: FAILED - No user profile entries found" -Level 'Warning'
            }
        } else {
            $ErrorMessages += "Cannot check registry entries - registry path does not exist"
            Write-LogMessage -Message "Registry Entries check: SKIPPED - Registry path does not exist" -Level 'Warning'
        }
    } catch {
        $ErrorMessages += "Error checking registry entries: $($_.Exception.Message)"
        Write-LogMessage -Message "Registry Entries check: FAILED - Error: $($_.Exception.Message)" -Level 'Error'
    }

    # Test 5: Check Version marker matches expected (drives upgrade redeploys)
    try {
        if ($DetectionResults.RegistryPath) {
            $InstalledVersion = (Get-ItemProperty -Path $Script:RegistryPath -Name Version -ErrorAction SilentlyContinue).Version
            if (-not $InstalledVersion) {
                $ErrorMessages += "Version marker missing from $($Script:RegistryPath)"
                Write-LogMessage -Message "Version Marker check: FAILED - Version property not present" -Level 'Warning'
            }
            elseif ($InstalledVersion -ne $Script:Config.ExpectedVersion) {
                $ErrorMessages += "Version mismatch: installed=$InstalledVersion expected=$($Script:Config.ExpectedVersion)"
                Write-LogMessage -Message "Version Marker check: FAILED - $InstalledVersion != $($Script:Config.ExpectedVersion)" -Level 'Warning'
            }
            else {
                $DetectionResults.VersionMarker = $true
                Write-LogMessage -Message "Version Marker check: PASSED - Installed $InstalledVersion matches expected" -Level 'Information'
            }
        } else {
            $ErrorMessages += "Cannot check Version marker - registry path does not exist"
            Write-LogMessage -Message "Version Marker check: SKIPPED - Registry path missing" -Level 'Warning'
        }
    } catch {
        $ErrorMessages += "Error checking Version marker: $($_.Exception.Message)"
        Write-LogMessage -Message "Version Marker check: FAILED - Error: $($_.Exception.Message)" -Level 'Error'
    }

    # Determine overall success
    $SuccessfulComponents = $DetectionResults.Values | Where-Object { $_ -eq $true } | Measure-Object
    $FailedComponents = @()

    # Check each component and build list of failures
    if (-not $DetectionResults.ScheduledTask) {
        $FailedComponents += "Scheduled Task"
    }
    if (-not $DetectionResults.ScriptFile) {
        $FailedComponents += "Script File"
    }
    if (-not $DetectionResults.RegistryPath) {
        $FailedComponents += "Registry Path"
    }
    if (-not $DetectionResults.RegistryEntries) {
        $FailedComponents += "Registry Entries"
    }
    if (-not $DetectionResults.VersionMarker) {
        $FailedComponents += "Version Marker"
    }

    # Determine installation status and exit code
    if ($SuccessfulComponents.Count -eq $Script:Config.RequiredComponents) {
        Write-LogMessage -Message "Detection complete: COMPLIANT - All $($Script:Config.RequiredComponents) components present and functional" -Level 'Information'
        Write-Output "True Logon system is fully compliant - all components present"
        exit 0  # Compliant
    } else {
        Write-LogMessage -Message "Detection complete: NON-COMPLIANT - $($SuccessfulComponents.Count)/$($Script:Config.RequiredComponents) components passed. Failed: $($FailedComponents -join ', ')" -Level 'Warning'
        Write-Output "True Logon system is not compliant"
        Write-Output "Failed components: $($FailedComponents -join ', ')"
        if ($ErrorMessages.Count -gt 0) {
            Write-Output "Detailed errors: $($ErrorMessages -join '; ')"
        }
        exit 1  # Non-compliant (will trigger remediation)
    }

} catch {
    Write-LogMessage -Message "Detection complete: CRITICAL ERROR - $($_.Exception.Message)" -Level 'Error'
    Write-Error "Critical error during detection: $($_.Exception.Message)"
    exit 2  # Error
}
