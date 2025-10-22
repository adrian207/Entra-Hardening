<#
.SYNOPSIS
    Centralized logging function for Entra ID hardening operations.

.DESCRIPTION
    Provides consistent logging across all modules with support for multiple log levels,
    file output, and structured logging for audit purposes.

.PARAMETER Message
    The message to log.

.PARAMETER Level
    Log level: Info, Warning, Error, Success, Debug, Verbose

.PARAMETER Component
    The component or module name generating the log entry.

.PARAMETER WriteToFile
    Write log entry to file (default: true).

.PARAMETER LogObject
    Optional object to serialize and log for audit purposes.

.EXAMPLE
    Invoke-EntraLogger -Message "MFA policy created" -Level Success -Component "MFA-Deployment"

.EXAMPLE
    Invoke-EntraLogger -Message "Failed to create policy" -Level Error -Component "CA-Deployment" -LogObject $policyDetails
#>

function Invoke-EntraLogger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug', 'Verbose')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory = $false)]
        [string]$Component = 'General',
        
        [Parameter(Mandatory = $false)]
        [bool]$WriteToFile = $true,
        
        [Parameter(Mandatory = $false)]
        [object]$LogObject = $null
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] [$Component] $Message"
    
    # Console output with color coding
    switch ($Level) {
        'Info'    { Write-Host $logEntry -ForegroundColor White }
        'Warning' { Write-Warning $logEntry }
        'Error'   { Write-Error $logEntry }
        'Success' { Write-Host $logEntry -ForegroundColor Green }
        'Debug'   { Write-Debug $logEntry }
        'Verbose' { Write-Verbose $logEntry }
    }
    
    # File output
    if ($WriteToFile) {
        $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $logDir = Join-Path $scriptRoot "Logs"
        
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        $logDate = Get-Date -Format 'yyyyMMdd'
        $logFile = Join-Path $logDir "EntraHardening-$logDate.log"
        
        # Append to log file
        Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
        
        # If there's a log object, serialize it to JSON log
        if ($LogObject) {
            $jsonLogFile = Join-Path $logDir "Changes-$logDate.json"
            
            $structuredLog = @{
                Timestamp = $timestamp
                Level = $Level
                Component = $Component
                Message = $Message
                Details = $LogObject
            }
            
            try {
                # Append to JSON array in file
                $existingLogs = @()
                if (Test-Path $jsonLogFile) {
                    $existingLogs = Get-Content $jsonLogFile -Raw | ConvertFrom-Json
                }
                
                $existingLogs += $structuredLog
                $existingLogs | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonLogFile
            }
            catch {
                Write-Warning "Failed to write structured log: $($_.Exception.Message)"
            }
        }
    }
}

# Export function
Export-ModuleMember -Function Invoke-EntraLogger

