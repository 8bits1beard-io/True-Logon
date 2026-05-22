#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs or uninstalls the True Logon system for monitoring user logon activity.

.DESCRIPTION
    Install.ps1 sets up or removes the True Logon user-logon tracking system.

    On install it:
      - Cleans up legacy task names and orphan system-SID entries left
        by older versions of the tool.
      - Creates HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon and writes Version and ScriptHash
        markers so Detection.ps1 can verify install integrity.
      - Seeds existing user profiles into the registry (idempotent - existing
        LastLogon values are preserved on upgrade).
      - Drops the tracker script to C:\ProgramData\TrueLogon\TrueLogon.ps1.
      - Registers the "TrueLogon" scheduled task to run the tracker as SYSTEM
        at every interactive logon.

    Per-user logon data (Username, LastLogon, ProfilePath) is stored in the
    registry under HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon\{SID}. Log files in
    C:\ProgramData\TrueLogon\Logs\ record install/uninstall operations and
    any tracker errors - they do not store routine per-logon data.

    Use -Uninstall to remove the task, script, and registry key. Logs are
    intentionally preserved for troubleshooting.

.AUTHOR
    Joshua Walderbach

.VERSION
    2.0.4

.CREATED
    2025-06-09

.LASTUPDATED
    2026-05-22

.PARAMETER Uninstall
    Switch parameter to remove the scheduled task, registry keys, and script files created by this system.
    When specified, performs complete cleanup of all True Logon components.

.PARAMETER WhatIf
    Switch parameter to run the script in simulation mode without actually making changes.
    Shows what would be installed or uninstalled without modifying the system.

.EXAMPLE
    # Basic Usage - Initialize Tracking System
    PS> .\Install.ps1
    Initializes the complete user logon tracking system including scheduled task and registry setup.

.EXAMPLE
    # Uninstall Mode - Remove All Components
    PS> .\Install.ps1 -Uninstall
    Removes the logon tracking system and all associated components including tasks, registry keys, and files.

.NOTES
    - Requires PowerShell 5.1 or later
    - Requires Administrator privileges for registry and scheduled task operations
    - No additional modules required - uses built-in Windows cmdlets
    - Script follows Microsoft PowerShell Best Practices and POSH Style Guide
    - Creates scheduled task running as SYSTEM account for security
    - All operations are logged with enterprise-grade audit trails
    - Use Get-Help Install.ps1 -Full for complete documentation
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage = "Remove the True Logon system and all associated components")]
    [switch]$Uninstall,

    [Parameter(HelpMessage = "Run in simulation mode without making changes")]
    [switch]$WhatIf
)

# Force 64-bit on a 64-bit OS. Intune's IME can launch Win32 install commands
# in 32-bit PowerShell depending on app config and host architecture; under
# WOW64 every write to HKLM:\SOFTWARE\Walmart\... is silently redirected to
# HKLM:\SOFTWARE\WOW6432Node\Walmart\..., and Detection (which runs 64-bit)
# can't see those keys. Relaunch ourselves in 64-bit before doing anything.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $Relaunch = Join-Path -Path $env:SystemRoot -ChildPath 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $RelaunchArgs = @('-ExecutionPolicy','Bypass','-NoProfile','-File',$PSCommandPath)
    if ($Uninstall) { $RelaunchArgs += '-Uninstall' }
    if ($WhatIf)    { $RelaunchArgs += '-WhatIf' }
    & $Relaunch @RelaunchArgs
    exit $LASTEXITCODE
}

$Script:RegistryPath = "HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon"
# Path the registry root maps to when this script is ever (re-)launched under
# WOW64 — covers pre-fix installs that wrote here and need migrating back.
$Script:WowRegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Walmart\WindowsEngineeringOS\TrueLogon"
# Keep this value in sync with $Script:Config.ExpectedVersion in Tracker/Detection.ps1
# and the Version field in both script headers. They must match exactly or
# Detection will mark every install non-compliant and Intune will redeploy.
$Script:Version = '2.0.4'
$Script:CriticalErrors = @()

# Users to never track or clean up. Must match $Script:DefaultExcludeUsers
# in ProactiveRemediationScripts/Remediation.ps1 exactly.
$Script:DefaultExcludeUsers = @("Default", "Default User", "Public", "All Users", "Administrator", "Moonpie")

# Path to the tracker script on disk. Referenced from the uninstall, script-write,
# and task-register blocks below. If renamed, the same name should be used in
# Tracker/Detection.ps1's $Script:TrackerScriptPath (each script owns its own copy).
$Script:TrackerScriptPath = 'C:\ProgramData\TrueLogon\TrueLogon.ps1'

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
        Default: 'Install'

    .PARAMETER LogPath
        The directory where the log file will be stored.
        Default: C:\ProgramData\TrueLogon\Logs

    .PARAMETER LogFileName
        The name of the log file.
        Default: TrueLogon.log

    .PARAMETER MaxFileSizeMB
        Maximum log file size in MB before rotation. Default: 5 MB

    .EXAMPLE
        Write-LogMessage -Message "Script started" -Level Information

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
        [string]$Component = 'Install',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPath = "C:\ProgramData\TrueLogon\Logs",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFileName = "TrueLogon-Install.log",

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
            $LogEntry = "<![LOG[$Message]LOG]!><time=`"$Time+$UtcOffset`" date=`"$Date`" component=`"$Component`" context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" type=`"$Type`" thread=`"$PID`" file=`"$($MyInvocation.ScriptName | Split-Path -Leaf)`">"

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

# Initialize logging
$whatIfText = if ($WhatIf) { " [WHATIF MODE]" } else { "" }
Write-LogMessage -Message "Install started$whatIfText - Uninstall: $Uninstall" -Level Information

# Clean up legacy scheduled tasks from previous versions of this tool.
# Uses schtasks.exe to avoid the slow scheduler-wide enumeration that
# Get-ScheduledTask performs on every call (see Tracker/Detection.ps1
# for the same fix). /Delete is a no-op when the task doesn't exist —
# exit code 0 means "removed", anything else means "wasn't there".
$LegacyTaskNames = @("User Logon Registry Stamp", "UserLogonTracking", "TrackUserLogon")
foreach ($LegacyTask in $LegacyTaskNames) {
    if ($WhatIf) {
        & schtasks.exe /Query /TN $LegacyTask 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage -Message "[WHATIF] Would remove legacy scheduled task '$LegacyTask'" -Level Information
            Write-Host "[WHATIF] Would remove legacy scheduled task '$LegacyTask'" -ForegroundColor Magenta
        }
    }
    else {
        & schtasks.exe /Delete /TN $LegacyTask /F 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage -Message "Legacy scheduled task '$LegacyTask' removed successfully" -Level Information
            Write-Host "Removed legacy scheduled task: $LegacyTask" -ForegroundColor Cyan
        }
    }
}

# Clean up orphan system-SID entries written by the pre-2.0.1 tracker bug
# (the old tracker resolved its own SYSTEM identity instead of the user's,
# so every logon stamped under S-1-5-18 / S-1-5-19 / S-1-5-20).
$LegacyOrphanSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
foreach ($OrphanSid in $LegacyOrphanSids) {
    $OrphanPath = Join-Path -Path $Script:RegistryPath -ChildPath $OrphanSid
    if (Test-Path $OrphanPath) {
        try {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove orphan system-SID entry '$OrphanPath'" -Level Information
                Write-Host "[WHATIF] Would remove orphan system-SID entry '$OrphanPath'" -ForegroundColor Magenta
            }
            else {
                Remove-Item -Path $OrphanPath -Recurse -Force -ErrorAction Stop
                Write-LogMessage -Message "Orphan system-SID entry '$OrphanPath' removed successfully" -Level Information
                Write-Host "Removed orphan system-SID entry: $OrphanPath" -ForegroundColor Cyan
            }
        }
        catch {
            Write-LogMessage -Message "Failed to remove orphan system-SID entry '$OrphanPath': $($_.Exception.Message)" -Level Warning
        }
    }
}

# Handle uninstall mode
if ($Uninstall) {
    Write-LogMessage -Message "Uninstall mode activated$whatIfText" -Level Information
    Write-Host "Uninstall mode activated. Reversing initialization..." -ForegroundColor Magenta

    # Track removal failures so we can report a nonzero exit code to Intune
    $UninstallErrors = 0

    # Remove scheduled task. Uses schtasks.exe to avoid the multi-second
    # scheduler-wide enumeration that Get-ScheduledTask performs on every call.
    $TaskName = "TrueLogon"
    if ($WhatIf) {
        & schtasks.exe /Query /TN $TaskName 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage -Message "[WHATIF] Would remove scheduled task '$TaskName'" -Level Information
            Write-Host "[WHATIF] Would remove scheduled task '$TaskName'" -ForegroundColor Magenta
        }
        else {
            Write-Host "Scheduled task '$TaskName' not found." -ForegroundColor Yellow
        }
    }
    else {
        $SchOutput = & schtasks.exe /Delete /TN $TaskName /F 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage -Message "Scheduled task '$TaskName' removed successfully" -Level Information
            Write-Host "Scheduled task '$TaskName' removed." -ForegroundColor Cyan
        }
        elseif ($SchOutput -match 'cannot find|does not exist') {
            Write-Host "Scheduled task '$TaskName' not found." -ForegroundColor Yellow
        }
        else {
            $UninstallErrors++
            Write-LogMessage -Message "Failed to remove scheduled task '$TaskName' (schtasks exit $LASTEXITCODE): $($SchOutput -join ' ')" -Level Error
            Write-Warning "Failed to remove scheduled task '$TaskName': $($SchOutput -join ' ')"
        }
    }

    # Remove script file
    $ScriptPath = $Script:TrackerScriptPath
    if (Test-Path $ScriptPath) {
        try {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove script file: $ScriptPath" -Level Information
                Write-Host "[WHATIF] Would remove script file: $ScriptPath" -ForegroundColor Magenta
            }
            else {
                Remove-Item -Path $ScriptPath -Force -ErrorAction Stop
                Write-LogMessage -Message "Script file removed: $ScriptPath" -Level Information
                Write-Host "Script file removed: $ScriptPath" -ForegroundColor Cyan
            }
        }
        catch {
            $UninstallErrors++
            Write-LogMessage -Message "Failed to remove script file '$ScriptPath': $($_.Exception.Message)" -Level Error
            Write-Warning "Failed to remove script file: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "$ScriptPath not found." -ForegroundColor Yellow
    }

    # Remove WOW6432Node copy if a prior 32-bit Install run left one behind.
    # Best-effort: failure here doesn't gate the uninstall exit code because
    # the data is already orphaned (Detection only ever looks at the native hive).
    if (Test-Path $Script:WowRegistryPath) {
        try {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove WOW6432Node registry key: $Script:WowRegistryPath" -Level Information
                Write-Host "[WHATIF] Would remove WOW6432Node registry key: $Script:WowRegistryPath" -ForegroundColor Magenta
            }
            else {
                Remove-Item -Path $Script:WowRegistryPath -Recurse -Force -ErrorAction Stop
                Write-LogMessage -Message "WOW6432Node registry key removed: $Script:WowRegistryPath" -Level Information
            }
        }
        catch {
            Write-LogMessage -Message "Failed to remove WOW6432Node registry key '$Script:WowRegistryPath': $($_.Exception.Message)" -Level Warning
        }
    }

    # Remove registry key
    if (Test-Path $Script:RegistryPath) {
        try {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove registry key: $Script:RegistryPath" -Level Information
                Write-Host "[WHATIF] Would remove registry key: $Script:RegistryPath" -ForegroundColor Magenta
            }
            else {
                Remove-Item -Path $Script:RegistryPath -Recurse -Force -ErrorAction Stop
                Write-LogMessage -Message "Registry key removed: $Script:RegistryPath" -Level Information
                Write-Host "Registry key removed: $Script:RegistryPath" -ForegroundColor Cyan
            }
        }
        catch {
            $UninstallErrors++
            Write-LogMessage -Message "Failed to remove registry key '$Script:RegistryPath': $($_.Exception.Message)" -Level Error
            Write-Warning "Failed to remove registry key: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "$Script:RegistryPath not found." -ForegroundColor Yellow
    }

    # Remove folder only if empty (logs are intentionally preserved for troubleshooting).
    # Folder-cleanup failures don't gate the uninstall exit code.
    $ScriptFolder = Split-Path -Path $ScriptPath -Parent
    if ((Test-Path $ScriptFolder) -and (-not (Get-ChildItem -Path $ScriptFolder -Force))) {
        try {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would remove empty folder: $ScriptFolder" -Level Information
                Write-Host "[WHATIF] Would remove empty folder: $ScriptFolder" -ForegroundColor Magenta
            }
            else {
                Remove-Item -Path $ScriptFolder -Force -ErrorAction Stop
                Write-LogMessage -Message "Empty folder removed: $ScriptFolder" -Level Information
                Write-Host "Removed empty folder: $ScriptFolder" -ForegroundColor Cyan
            }
        }
        catch {
            Write-LogMessage -Message "Failed to remove folder '$ScriptFolder': $($_.Exception.Message)" -Level Error
            Write-Warning "Failed to remove folder '$ScriptFolder': $($_.Exception.Message)"
        }
    }
    elseif (Test-Path $ScriptFolder) {
        Write-LogMessage -Message "Folder preserved (contains logs): $ScriptFolder" -Level Information
        Write-Host "Logs preserved at: $ScriptFolder\Logs\" -ForegroundColor Cyan
    }

    if ($UninstallErrors -gt 0) {
        Write-LogMessage -Message "Uninstall completed with $UninstallErrors error(s)$whatIfText - exiting 1" -Level Error
        exit 1
    }
    Write-LogMessage -Message "Uninstall process completed$whatIfText" -Level Information
    exit 0
}

function Initialize-UserLogonRegistry {
    [CmdletBinding()]
    param (
        [string]$RegistryPath = $Script:RegistryPath,
        [string[]]$ExcludeUsers = $Script:DefaultExcludeUsers,
        [switch]$WhatIf
    )

    $whatIfText = if ($WhatIf) { " [WHATIF]" } else { "" }
    Write-LogMessage -Message "Initialize-UserLogonRegistry started$whatIfText" -Level Information

    # Seed LastLogon from each profile folder's LastWriteTime (computed per-profile
    # below). It's an approximation, but a much better one than "today" — seeding
    # with the install date would force a full grace period before any pre-existing
    # profile became eligible for cleanup, even ones already dormant for months.
    # The tracker overwrites this with a real timestamp on the user's next logon.
    $AddedCount = 0
    $RefreshedCount = 0

    try {
        if (-not (Test-Path $RegistryPath)) {
            if ($WhatIf) {
                Write-LogMessage -Message "[WHATIF] Would create registry path: $RegistryPath" -Level Information
            }
            else {
                New-Item -Path $RegistryPath -Force -ErrorAction Stop | Out-Null
                Write-LogMessage -Message "Registry path created: $RegistryPath" -Level Information
            }
        }

        # Only seed real interactive user SIDs. System/service profiles would
        # never be updated by the SID-guarded tracker anyway.
        $UserProfiles = Get-CimInstance -ClassName Win32_UserProfile |
            Where-Object { -not $_.Special -and $_.SID -match '^S-1-5-21-' }
        Write-LogMessage -Message "Found $($UserProfiles.Count) interactive user profiles" -Level Information

        $UserProfiles | ForEach-Object {
            $ProfilePath = $_.LocalPath
            $ProfileName = Split-Path -Path $ProfilePath -Leaf
            $ProfileSid = $_.SID

            if ($ExcludeUsers -contains $ProfileName) {
                return
            }

            $SidRegistryPath = Join-Path -Path $RegistryPath -ChildPath $ProfileSid

            try {
                # Idempotent seed: preserve LastLogon if a previous install or
                # the tracker has already written one. Without this guard, every
                # install/upgrade/redeploy would reset every user's real logon
                # history to the install date.
                $existingLogon = $null
                if (Test-Path $SidRegistryPath) {
                    $existingLogon = (Get-ItemProperty -Path $SidRegistryPath -Name LastLogon -ErrorAction SilentlyContinue).LastLogon
                }

                $SeedTimestamp = $null
                if (-not $existingLogon) {
                    $SeedSource = if (Test-Path -LiteralPath $ProfilePath) {
                        try {
                            (Get-Item -LiteralPath $ProfilePath -Force -ErrorAction Stop).LastWriteTime
                        } catch {
                            Get-Date
                        }
                    } else {
                        Get-Date
                    }
                    $SeedTimestamp = $SeedSource.ToString("yyyy-MM-ddTHH:mm:ss")
                }

                if ($WhatIf) {
                    if ($existingLogon) {
                        $RefreshedCount++
                        Write-LogMessage -Message "[WHATIF] Would refresh metadata for SID '$ProfileSid' (user '$ProfileName'); preserving existing LastLogon: $existingLogon" -Level Information
                    }
                    else {
                        $AddedCount++
                        Write-LogMessage -Message "[WHATIF] Would seed SID '$ProfileSid' (user '$ProfileName') with LastLogon: $SeedTimestamp" -Level Information
                    }
                }
                else {
                    # Always ensure key exists and refresh Username/ProfilePath
                    # (cheap, and they can legitimately change — e.g. profile rename)
                    New-Item -Path $SidRegistryPath -Force | Out-Null
                    New-ItemProperty -Path $SidRegistryPath -Name "Username" -Value $ProfileName -PropertyType String -Force | Out-Null
                    New-ItemProperty -Path $SidRegistryPath -Name "ProfilePath" -Value $ProfilePath -PropertyType String -Force | Out-Null

                    if ($existingLogon) {
                        $RefreshedCount++
                        Write-LogMessage -Message "Refreshed metadata for SID '$ProfileSid' (user '$ProfileName'); preserving LastLogon: $existingLogon" -Level Information
                    }
                    else {
                        New-ItemProperty -Path $SidRegistryPath -Name "LastLogon" -Value $SeedTimestamp -PropertyType String -Force | Out-Null
                        $AddedCount++
                        Write-LogMessage -Message "Seeded SID '$ProfileSid' (user '$ProfileName') with LastLogon: $SeedTimestamp" -Level Information
                    }
                }
            }
            catch {
                Write-LogMessage -Message "Failed to write profile SID '$ProfileSid' to registry: $($_.Exception.Message)" -Level Error
                Write-Warning "An error occurred while writing $ProfileSid to registry: $_"
                $Script:CriticalErrors += "Registry seeding failed for SID '$ProfileSid' (user '$ProfileName'): $($_.Exception.Message)"
            }
        }

        Write-LogMessage -Message "User profile processing completed$whatIfText. Newly seeded: $AddedCount. Existing entries preserved: $RefreshedCount." -Level Information
        Write-Host "Newly seeded profiles: $AddedCount   Existing entries preserved: $RefreshedCount"

        if ($AddedCount -eq 0 -and $RefreshedCount -eq 0 -and -not $WhatIf) {
            Write-LogMessage -Message "Registry has no interactive user profiles (machine may have no interactive users yet - profiles will be added on first logon)" -Level Warning
        }
    }
    catch {
        Write-LogMessage -Message "Critical error occurred during registry initialization: $($_.Exception.Message)" -Level Error
        Write-Warning "An error occurred during initialization: $_"
        $Script:CriticalErrors += "Registry initialization failed: $($_.Exception.Message)"
    }
}

# One-shot migration: anything previously written by a 32-bit Install run is
# sitting in WOW6432Node and is orphaned now that we're consistently 64-bit.
# Copy its Version/ScriptHash and every S-1-5-21-* child (with Username,
# LastLogon, ProfilePath) into the native hive, then remove the WOW6432Node
# copy so we don't carry duplicate state. Preserves tracked LastLogon history
# across the bitness fix; without this, every existing device would lose its
# accumulated logon timestamps and re-seed from profile-folder LastWriteTime.
if (-not $WhatIf -and (Test-Path $Script:WowRegistryPath)) {
    try {
        if (-not (Test-Path $Script:RegistryPath)) {
            New-Item -Path $Script:RegistryPath -Force -ErrorAction Stop | Out-Null
        }

        $WowRoot = Get-ItemProperty -Path $Script:WowRegistryPath -ErrorAction SilentlyContinue
        foreach ($PropName in @('Version','ScriptHash')) {
            if ($WowRoot -and ($WowRoot.PSObject.Properties.Name -contains $PropName)) {
                New-ItemProperty -Path $Script:RegistryPath -Name $PropName -Value $WowRoot.$PropName -PropertyType String -Force | Out-Null
            }
        }

        $MigratedSids = 0
        Get-ChildItem -Path $Script:WowRegistryPath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
            ForEach-Object {
                $DestPath = Join-Path -Path $Script:RegistryPath -ChildPath $_.PSChildName
                if (-not (Test-Path $DestPath)) {
                    New-Item -Path $DestPath -Force | Out-Null
                }
                $Child = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                foreach ($PropName in @('Username','LastLogon','ProfilePath')) {
                    if ($Child -and ($Child.PSObject.Properties.Name -contains $PropName)) {
                        New-ItemProperty -Path $DestPath -Name $PropName -Value $Child.$PropName -PropertyType String -Force | Out-Null
                    }
                }
                $MigratedSids++
            }

        Remove-Item -Path $Script:WowRegistryPath -Recurse -Force -ErrorAction Stop
        Write-LogMessage -Message "Migrated TrueLogon registry data from WOW6432Node to native hive ($MigratedSids user SID(s))" -Level Information
    }
    catch {
        Write-LogMessage -Message "WOW6432Node migration failed: $($_.Exception.Message)" -Level Error
        $Script:CriticalErrors += "WOW6432Node migration failed: $($_.Exception.Message)"
    }
}

# Run the initialization
Initialize-UserLogonRegistry -WhatIf:$WhatIf

# Write version marker at script level (install-time concern, not part of
# logon-registry init). Runs on every install so upgrades update it in place.
if ($WhatIf) {
    Write-LogMessage -Message "[WHATIF] Would set Version=$Script:Version at $Script:RegistryPath" -Level Information
}
elseif (Test-Path $Script:RegistryPath) {
    try {
        New-ItemProperty -Path $Script:RegistryPath -Name "Version" -Value $Script:Version -PropertyType String -Force | Out-Null
        Write-LogMessage -Message "Version marker set: $Script:Version" -Level Information
    }
    catch {
        Write-LogMessage -Message "Failed to write Version marker: $($_.Exception.Message)" -Level Error
        $Script:CriticalErrors += "Version marker write failed: $($_.Exception.Message)"
    }
}
else {
    Write-LogMessage -Message "Cannot write Version marker - registry path missing: $Script:RegistryPath" -Level Warning
    $Script:CriticalErrors += "Version marker not written - registry path missing"
}

try {

# Define the logon tracking script content
$TrueLogon_Script = @'
# SYSTEM-scheduled-tasks normally launch the 64-bit PowerShell via System32's
# PATH precedence, but belt-and-suspenders: if for any reason we end up in
# 32-bit, relaunch so registry writes hit the native hive (and match what
# Install.ps1 and Detection.ps1 expect).
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $Relaunch = Join-Path -Path $env:SystemRoot -ChildPath 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    & $Relaunch -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File $PSCommandPath
    exit $LASTEXITCODE
}

function Enable-TrueLogon {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$RegistryPath = "HKLM:\SOFTWARE\Walmart\WindowsEngineeringOS\TrueLogon",

        [Parameter()]
        [string]$LogPath = "C:\ProgramData\TrueLogon\Logs\TrueLogon-Tracking.log"
    )

    # CMTrace-format tracking log writer. Every bail-out path uses this so
    # silent failures are observable from the log file.
    function Write-TrackingLog {
        param(
            [string]$Message,
            [int]$Type = 3,
            [string]$User = 'Tracking'
        )
        try {
            $LogDir = Split-Path -Path $LogPath -Parent
            if (-not (Test-Path $LogDir)) {
                New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            }
            $Now = Get-Date
            $Time = $Now.ToString("HH:mm:ss.fff")
            $Date = $Now.ToString("MM-dd-yyyy")
            $UtcOffset = [System.TimeZoneInfo]::Local.GetUtcOffset($Now).TotalMinutes
            $LogEntry = "<![LOG[$Message]LOG]!><time=`"$Time+$UtcOffset`" date=`"$Date`" component=`"Tracking`" context=`"$User`" type=`"$Type`" thread=`"$PID`" file=`"TrueLogon.ps1`">"
            Add-Content -Path $LogPath -Value $LogEntry -ErrorAction SilentlyContinue
        } catch {
            # Never block logon, even if logging fails
        }
    }

    $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $SafeUsername = "UnknownUser"

    # Identify the interactive console user. Cannot use WindowsIdentity::GetCurrent()
    # here because this script runs as SYSTEM, which would resolve to S-1-5-18.
    # WMI can return empty during fast user switching / RDP transitions, so retry.
    $Session = $null
    for ($i = 1; $i -le 3; $i++) {
        $Session = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
        if ($Session -and $Session -match '\\') { break }
        if ($i -lt 3) { Start-Sleep -Milliseconds 500 }
    }

    if (-not $Session -or $Session -notmatch '\\') {
        Write-TrackingLog -Message "Skipped: Win32_ComputerSystem.UserName was empty or malformed after 3 attempts"
        return $false
    }

    $Domain, $Username = $Session -split '\\', 2
    $SafeUsername = $Username -replace '[\\/:*?"<>|]', '_'

    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($Domain, $Username)
        $UserSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        Write-TrackingLog -Message "Skipped: failed to translate '$Domain\$Username' to SID: $($_.Exception.Message)" -User $SafeUsername
        return $false
    }

    # Only stamp real interactive user SIDs, never system or service accounts
    if (-not $UserSid -or $UserSid -notmatch '^S-1-5-21-') {
        Write-TrackingLog -Message "Skipped: resolved SID '$UserSid' is not an interactive user SID" -User $SafeUsername
        return $false
    }

    # Profile path must come from Win32_UserProfile keyed by SID.
    # $env:USERPROFILE under SYSTEM resolves to C:\Windows\System32\config\systemprofile.
    $ProfilePath = $null
    try {
        $UserProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$UserSid'" -ErrorAction SilentlyContinue
        if ($UserProfile) {
            $ProfilePath = $UserProfile.LocalPath
        }
    } catch {
        $ProfilePath = $null
    }

    try {
        if (-not (Test-Path $RegistryPath)) {
            New-Item -Path $RegistryPath -Force | Out-Null
        }

        $SidRegistryPath = Join-Path -Path $RegistryPath -ChildPath $UserSid
        if (-not (Test-Path $SidRegistryPath)) {
            New-Item -Path $SidRegistryPath -Force | Out-Null
        }

        New-ItemProperty -Path $SidRegistryPath -Name "LastLogon" -Value $Timestamp -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $SidRegistryPath -Name "Username" -Value $SafeUsername -PropertyType String -Force | Out-Null
        if ($ProfilePath) {
            New-ItemProperty -Path $SidRegistryPath -Name "ProfilePath" -Value $ProfilePath -PropertyType String -Force | Out-Null
        }
        return $true
    } catch {
        Write-TrackingLog -Message "Failed to record logon for user '$SafeUsername': $($_.Exception.Message)" -User $SafeUsername
        return $false
    }
}

Enable-TrueLogon
'@

# Save the script to disk
try {
    $ScriptPath = $Script:TrackerScriptPath
    $ScriptDirectory = Split-Path -Path $ScriptPath -Parent

    if (-not (Test-Path $ScriptDirectory)) {
        if ($WhatIf) {
            Write-LogMessage -Message "[WHATIF] Would create script directory: $ScriptDirectory" -Level Information
        }
        else {
            New-Item -ItemType Directory -Path $ScriptDirectory -Force | Out-Null
            Write-LogMessage -Message "Script directory created: $ScriptDirectory" -Level Information
        }
    }

    if ($WhatIf) {
        Write-LogMessage -Message "[WHATIF] Would create True Logon script file: $ScriptPath" -Level Information
        Write-LogMessage -Message "[WHATIF] Would record tracker script SHA256 hash at $Script:RegistryPath\ScriptHash" -Level Information
    }
    else {
        Set-Content -Path $ScriptPath -Value $TrueLogon_Script -Force -Encoding UTF8
        Write-LogMessage -Message "True Logon script file created: $ScriptPath" -Level Information

        # Record SHA256 of the file so Detection.ps1 can verify integrity on
        # every detection cycle. A mismatch (tamper, partial write, or stale
        # install) trips a redeploy.
        try {
            $ScriptHash = (Get-FileHash -Path $ScriptPath -Algorithm SHA256 -ErrorAction Stop).Hash
            New-ItemProperty -Path $Script:RegistryPath -Name "ScriptHash" -Value $ScriptHash -PropertyType String -Force | Out-Null
            Write-LogMessage -Message "Tracker script SHA256 recorded: $ScriptHash" -Level Information
        }
        catch {
            Write-LogMessage -Message "Failed to record tracker script hash: $($_.Exception.Message)" -Level Error
            $Script:CriticalErrors += "Tracker script hash write failed: $($_.Exception.Message)"
        }
    }
}
catch {
    Write-LogMessage -Message "Failed to create True Logon script file '$ScriptPath': $($_.Exception.Message)" -Level Error
    Write-Warning "Failed to write tracking script: $_"
    $Script:CriticalErrors += "Script file creation failed: $($_.Exception.Message)"
}

# Register the scheduled task
try {
    $TaskName = "TrueLogon"
    $ScriptPath = $Script:TrackerScriptPath

    if ($WhatIf) {
        Write-LogMessage -Message "[WHATIF] Would register scheduled task '$TaskName' to run at logon as SYSTEM (Script: $ScriptPath)" -Level Information
    }
    else {
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$ScriptPath`""

        $Trigger = New-ScheduledTaskTrigger -AtLogOn

        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

        $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Description "Tracks user logons and updates registry with timestamp"

        Register-ScheduledTask -TaskName $TaskName -InputObject $Task -Force
        Write-LogMessage -Message "Scheduled task '$TaskName' registered successfully" -Level Information
    }
}
catch {
    Write-LogMessage -Message "Failed to register scheduled task '$TaskName': $($_.Exception.Message)" -Level Error
    Write-Warning "Scheduled task registration failed: $_"
    $Script:CriticalErrors += "Scheduled task registration failed: $($_.Exception.Message)"
}

# Determine final exit code based on critical errors
if ($Script:CriticalErrors.Count -gt 0) {
    Write-LogMessage -Message "Installation completed with $($Script:CriticalErrors.Count) critical error(s):" -Level Error
    foreach ($err in $Script:CriticalErrors) {
        Write-LogMessage -Message "  - $err" -Level Error
    }
    Write-LogMessage -Message "Install FAILED$whatIfText - Review errors above for details" -Level Error
    exit 1
}

# Script execution completed
Write-LogMessage -Message "True Logon system installation completed successfully$whatIfText" -Level Information
exit 0

} catch {
    Write-LogMessage -Message "UNEXPECTED CRITICAL ERROR during installation: $($_.Exception.Message)" -Level Error
    Write-LogMessage -Message "Stack trace: $($_.ScriptStackTrace)" -Level Error
    Write-Error "Critical error during installation: $($_.Exception.Message)"
    exit 1
}
