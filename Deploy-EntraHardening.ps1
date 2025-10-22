<#
.SYNOPSIS
    Main orchestration script for Entra ID hardening deployment.

.DESCRIPTION
    Coordinates the deployment of all Entra ID security hardening modules in a phased approach.
    Can deploy all phases or specific phases based on the implementation roadmap.

.PARAMETER Phase
    Deployment phase: 1 (Immediate), 2 (Core), 3 (Advanced), or All

.PARAMETER WhatIf
    Preview changes without applying them.

.PARAMETER ModulesPath
    Path to the modules directory. Defaults to .\Modules

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to .\config.json

.EXAMPLE
    .\Deploy-EntraHardening.ps1 -Phase 1 -WhatIf

.EXAMPLE
    .\Deploy-EntraHardening.ps1 -Phase All

.EXAMPLE
    .\Deploy-EntraHardening.ps1 -Phase 2
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('1', '2', '3', 'All')]
    [string]$Phase = '1',
    
    [Parameter(Mandatory = $false)]
    [string]$ModulesPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath
)

# Script root and paths
$scriptRoot = $PSScriptRoot
if (-not $ModulesPath) {
    $ModulesPath = Join-Path $scriptRoot "Modules"
}
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot "config.json"
}

# Import common functions
$commonPath = Join-Path $scriptRoot "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")

function Write-PhaseHeader {
    param([string]$PhaseName, [string]$Description)
    
    Write-Host "`n" -NoNewline
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " $PhaseName" -ForegroundColor Cyan
    Write-Host " $Description" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
}

function Invoke-ModuleScript {
    param(
        [string]$ModulePath,
        [string]$ModuleName,
        [hashtable]$Parameters = @{}
    )
    
    Write-Host "`nExecuting: $ModuleName" -ForegroundColor Yellow
    Write-Host "Script: $ModulePath" -ForegroundColor Gray
    
    if (-not (Test-Path $ModulePath)) {
        Write-Warning "Module not found: $ModulePath"
        return $false
    }
    
    try {
        $params = $Parameters.Clone()
        if ($WhatIfPreference) {
            $params['WhatIf'] = $true
        }
        
        & $ModulePath @params
        
        Write-Host "[✓] Completed: $ModuleName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to execute $ModuleName : $($_.Exception.Message)"
        return $false
    }
}

function Start-Phase1 {
    Write-PhaseHeader "PHASE 1: Immediate Actions" "Critical security controls (Week 1-2)"
    
    $modules = @(
        @{
            Name = "Break-Glass Accounts"
            Path = Join-Path $ModulesPath "4-BreakGlass\New-BreakGlassAccount.ps1"
            Description = "Create emergency access accounts"
        },
        @{
            Name = "MFA for Administrators"
            Path = Join-Path $ModulesPath "1-MFA-Authentication\Deploy-MFA.ps1"
            Description = "Enforce MFA for admin accounts"
            Parameters = @{ AdminsOnly = $true }
        },
        @{
            Name = "Block Legacy Authentication"
            Path = Join-Path $ModulesPath "1-MFA-Authentication\Block-LegacyAuth.ps1"
            Description = "Block legacy auth protocols"
            Parameters = @{ ReportOnly = $true }
        },
        @{
            Name = "Named Locations"
            Path = Join-Path $ModulesPath "2-ConditionalAccess\Deploy-NamedLocations.ps1"
            Description = "Configure trusted network locations"
        },
        @{
            Name = "Emergency CA Policies"
            Path = Join-Path $ModulesPath "2-ConditionalAccess\New-EmergencyCAPolicy.ps1"
            Description = "Create disabled emergency policies"
        }
    )
    
    $results = @()
    foreach ($module in $modules) {
        Write-Host "`n--------------------------------------------------" -ForegroundColor Gray
        $params = if ($module.Parameters) { $module.Parameters } else { @{} }
        $result = Invoke-ModuleScript -ModulePath $module.Path -ModuleName $module.Name -Parameters $params
        $results += @{ Module = $module.Name; Success = $result }
    }
    
    return $results
}

function Start-Phase2 {
    Write-PhaseHeader "PHASE 2: Core Hardening" "Essential security controls (Month 1)"
    
    $modules = @(
        @{
            Name = "MFA for All Users"
            Path = Join-Path $ModulesPath "1-MFA-Authentication\Deploy-MFA.ps1"
            Description = "Roll out MFA to all users"
        },
        @{
            Name = "Baseline Conditional Access"
            Path = Join-Path $ModulesPath "2-ConditionalAccess\Deploy-BaselineCA.ps1"
            Description = "Deploy baseline CA policies"
        },
        @{
            Name = "PIM for Global Administrators"
            Path = Join-Path $ModulesPath "3-PIM\Deploy-PIM.ps1"
            Description = "Enable PIM for privileged roles"
        },
        @{
            Name = "Audit Logging"
            Path = Join-Path $ModulesPath "5-Monitoring\Deploy-AuditLogging.ps1"
            Description = "Configure audit log retention"
        },
        @{
            Name = "Application Consent Restriction"
            Path = Join-Path $ModulesPath "6-ApplicationSecurity\Restrict-AppConsent.ps1"
            Description = "Disable user app consent"
        }
    )
    
    $results = @()
    foreach ($module in $modules) {
        Write-Host "`n--------------------------------------------------" -ForegroundColor Gray
        $params = if ($module.Parameters) { $module.Parameters } else { @{} }
        $result = Invoke-ModuleScript -ModulePath $module.Path -ModuleName $module.Name -Parameters $params
        $results += @{ Module = $module.Name; Success = $result }
    }
    
    return $results
}

function Start-Phase3 {
    Write-PhaseHeader "PHASE 3: Advanced Security" "Advanced controls (Month 2-3)"
    
    $modules = @(
        @{
            Name = "Passwordless Authentication"
            Path = Join-Path $ModulesPath "1-MFA-Authentication\Deploy-PasswordlessAuth.ps1"
            Description = "Enable passwordless auth methods"
        },
        @{
            Name = "B2B Collaboration Hardening"
            Path = Join-Path $ModulesPath "7-ExternalCollaboration\Harden-B2BSettings.ps1"
            Description = "Secure external collaboration"
        },
        @{
            Name = "Password Protection"
            Path = Join-Path $ModulesPath "8-PasswordProtection\Deploy-PasswordProtection.ps1"
            Description = "Deploy password protection"
        },
        @{
            Name = "Enterprise Apps Audit"
            Path = Join-Path $ModulesPath "6-ApplicationSecurity\Audit-EnterpriseApps.ps1"
            Description = "Audit registered applications"
            Parameters = @{ ExportReport = $true }
        }
    )
    
    $results = @()
    foreach ($module in $modules) {
        Write-Host "`n--------------------------------------------------" -ForegroundColor Gray
        $params = if ($module.Parameters) { $module.Parameters } else { @{} }
        $result = Invoke-ModuleScript -ModulePath $module.Path -ModuleName $module.Name -Parameters $params
        $results += @{ Module = $module.Name; Success = $result }
    }
    
    return $results
}

# Main execution
try {
    Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        Microsoft Entra ID Security Hardening             ║
║        Automated Deployment Orchestrator                 ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    Write-Host "Starting deployment..." -ForegroundColor Gray
    Write-Host "Phase: $Phase" -ForegroundColor Yellow
    Write-Host "WhatIf Mode: $WhatIfPreference" -ForegroundColor Yellow
    
    # Load and validate configuration
    Write-Host "`nValidating configuration..." -ForegroundColor Cyan
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config) {
        Write-Error "Failed to load configuration. Exiting."
        exit 1
    }
    
    Write-Host "[✓] Configuration validated" -ForegroundColor Green
    
    # Connect to Microsoft Graph
    Write-Host "`nChecking Microsoft Graph connection..." -ForegroundColor Cyan
    $context = Get-MgContext
    
    if (-not $context) {
        Write-Host "Not connected to Microsoft Graph." -ForegroundColor Yellow
        Write-Host "Attempting to connect..." -ForegroundColor Gray
        
        $connectScript = Join-Path $commonPath "Connect-EntraID.ps1"
        & $connectScript
        
        $context = Get-MgContext
        if (-not $context) {
            Write-Error "Failed to connect to Microsoft Graph. Exiting."
            exit 1
        }
    }
    
    Write-Host "[✓] Connected to tenant: $($context.TenantId)" -ForegroundColor Green
    
    # Execute deployment phases
    $startTime = Get-Date
    $allResults = @()
    
    if ($Phase -eq '1' -or $Phase -eq 'All') {
        $phase1Results = Start-Phase1
        $allResults += $phase1Results
        
        if ($Phase -eq '1') {
            Write-Host "`n[Important] After Phase 1 completion:" -ForegroundColor Yellow
            Write-Host "1. Secure break-glass credentials in physical safes" -ForegroundColor Gray
            Write-Host "2. Review CA policies in report-only mode for 7 days" -ForegroundColor Gray
            Write-Host "3. Ensure admin MFA enrollment before enforcing" -ForegroundColor Gray
        }
    }
    
    if ($Phase -eq '2' -or $Phase -eq 'All') {
        if ($Phase -eq 'All') {
            Write-Host "`n[Pause] Review Phase 1 results before proceeding to Phase 2" -ForegroundColor Yellow
            $continue = Read-Host "Continue to Phase 2? (Y/N)"
            if ($continue -ne 'Y') {
                Write-Host "Deployment paused. Run with -Phase 2 to continue later." -ForegroundColor Yellow
                exit 0
            }
        }
        
        $phase2Results = Start-Phase2
        $allResults += $phase2Results
    }
    
    if ($Phase -eq '3' -or $Phase -eq 'All') {
        if ($Phase -eq 'All') {
            Write-Host "`n[Pause] Review Phase 2 results before proceeding to Phase 3" -ForegroundColor Yellow
            $continue = Read-Host "Continue to Phase 3? (Y/N)"
            if ($continue -ne 'Y') {
                Write-Host "Deployment paused. Run with -Phase 3 to continue later." -ForegroundColor Yellow
                exit 0
            }
        }
        
        $phase3Results = Start-Phase3
        $allResults += $phase3Results
    }
    
    # Final summary
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "`n" -NoNewline
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Deployment Summary" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    Write-Host "`nPhase(s) Deployed: $Phase" -ForegroundColor Gray
    Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
    Write-Host "Total Modules: $($allResults.Count)" -ForegroundColor Gray
    
    $successful = ($allResults | Where-Object { $_.Success }).Count
    $failed = $allResults.Count - $successful
    
    Write-Host "`nResults:" -ForegroundColor Cyan
    Write-Host "  Successful: $successful" -ForegroundColor Green
    Write-Host "  Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Gray' })
    
    if ($failed -gt 0) {
        Write-Host "`nFailed Modules:" -ForegroundColor Red
        foreach ($result in ($allResults | Where-Object { -not $_.Success })) {
            Write-Host "  [✗] $($result.Module)" -ForegroundColor Red
        }
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    
    switch ($Phase) {
        '1' {
            Write-Host "1. Secure break-glass credentials physically" -ForegroundColor Gray
            Write-Host "2. Monitor CA policies in report-only mode (7 days)" -ForegroundColor Gray
            Write-Host "3. Prepare for Phase 2 deployment" -ForegroundColor Gray
            Write-Host "4. Run: .\Deploy-EntraHardening.ps1 -Phase 2" -ForegroundColor Yellow
        }
        '2' {
            Write-Host "1. Monitor MFA enrollment progress" -ForegroundColor Gray
            Write-Host "2. Review audit logs for compliance" -ForegroundColor Gray
            Write-Host "3. Convert permanent admin roles to PIM eligible" -ForegroundColor Gray
            Write-Host "4. Prepare for Phase 3 deployment" -ForegroundColor Gray
            Write-Host "5. Run: .\Deploy-EntraHardening.ps1 -Phase 3" -ForegroundColor Yellow
        }
        '3' {
            Write-Host "1. Promote passwordless authentication adoption" -ForegroundColor Gray
            Write-Host "2. Review and clean up inactive guest accounts" -ForegroundColor Gray
            Write-Host "3. Remove suspicious enterprise applications" -ForegroundColor Gray
            Write-Host "4. Schedule ongoing maintenance and reviews" -ForegroundColor Gray
        }
        'All' {
            Write-Host "1. Complete all manual configuration steps" -ForegroundColor Gray
            Write-Host "2. Review all generated reports" -ForegroundColor Gray
            Write-Host "3. Test emergency procedures (break-glass, emergency CA)" -ForegroundColor Gray
            Write-Host "4. Document current security posture" -ForegroundColor Gray
            Write-Host "5. Schedule quarterly security reviews" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nDocumentation:" -ForegroundColor Cyan
    Write-Host "  - Review README.md for detailed information" -ForegroundColor Gray
    Write-Host "  - Check Logs\ directory for execution logs" -ForegroundColor Gray
    Write-Host "  - Review Rollback\ directory for rollback files" -ForegroundColor Gray
    Write-Host "  - See Reports\ directory for audit reports" -ForegroundColor Gray
    
    Write-Host "`nContinuous Monitoring:" -ForegroundColor Yellow
    Write-Host "  - Schedule: .\Modules\4-BreakGlass\Monitor-BreakGlassActivity.ps1 (daily)" -ForegroundColor Gray
    Write-Host "  - Schedule: .\Modules\6-ApplicationSecurity\Audit-EnterpriseApps.ps1 (monthly)" -ForegroundColor Gray
    Write-Host "  - Review sign-in logs and CA policy impact regularly" -ForegroundColor Gray
    
    Write-Host "`n[✓] Deployment completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

