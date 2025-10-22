<#
.SYNOPSIS
    Creates a rollback file to revert changes made by hardening scripts.

.DESCRIPTION
    Generates a JSON file containing the state before changes, allowing for safe rollback
    of Entra ID modifications.

.PARAMETER Component
    The component or module creating the rollback file.

.PARAMETER BeforeState
    The state before changes were made.

.PARAMETER AfterState
    The state after changes were made.

.PARAMETER ChangeDescription
    Description of what was changed.

.EXAMPLE
    New-RollbackFile -Component "ConditionalAccess" -BeforeState $oldPolicies -AfterState $newPolicies -ChangeDescription "Created baseline CA policies"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Component,
    
    [Parameter(Mandatory = $true)]
    [object]$BeforeState,
    
    [Parameter(Mandatory = $false)]
    [object]$AfterState,
    
    [Parameter(Mandatory = $true)]
    [string]$ChangeDescription
)

try {
    # Create rollback directory if it doesn't exist
    $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $rollbackDir = Join-Path $scriptRoot "Rollback"
    
    if (-not (Test-Path $rollbackDir)) {
        New-Item -ItemType Directory -Path $rollbackDir -Force | Out-Null
    }
    
    # Create rollback file with timestamp
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $rollbackFileName = "$timestamp-$Component.json"
    $rollbackFilePath = Join-Path $rollbackDir $rollbackFileName
    
    # Create rollback object
    $rollbackData = @{
        Timestamp = Get-Date -Format 'o'
        Component = $Component
        Description = $ChangeDescription
        BeforeState = $BeforeState
        AfterState = $AfterState
        RollbackInstructions = @{
            Manual = "Review BeforeState and manually revert changes in Entra ID portal"
            Automated = "Use Restore-EntraChanges.ps1 -RollbackFile '$rollbackFilePath'"
        }
    }
    
    # Save to JSON file
    $rollbackData | ConvertTo-Json -Depth 10 | Set-Content -Path $rollbackFilePath -ErrorAction Stop
    
    Write-Host "Rollback file created: $rollbackFileName" -ForegroundColor Green
    Write-Verbose "Rollback file path: $rollbackFilePath"
    
    return $rollbackFilePath
}
catch {
    Write-Error "Failed to create rollback file: $($_.Exception.Message)"
    return $null
}

