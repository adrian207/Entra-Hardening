<#
.SYNOPSIS
    Creates emergency Conditional Access policies for disaster recovery.

.DESCRIPTION
    Creates disabled Conditional Access policies that can be quickly enabled during
    emergencies or outages (e.g., MFA service disruption, authentication issues).

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    .\New-EmergencyCAPolicy.ps1 -WhatIf

.EXAMPLE
    .\New-EmergencyCAPolicy.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function New-EmergencyPolicy {
    param(
        [string]$Name,
        [string]$Description,
        [object]$Conditions,
        [object]$GrantControls,
        [int]$PolicyNumber,
        [int]$TotalPolicies
    )
    
    $policyName = "EM$('{0:D2}' -f $PolicyNumber) - ENABLE IN EMERGENCY: $Name [$PolicyNumber/$TotalPolicies]"
    
    $policy = @{
        displayName = $policyName
        state = "disabled"
        conditions = $Conditions
        grantControls = $GrantControls
    }
    
    if ($PSCmdlet.ShouldProcess($policyName, "Create Emergency CA Policy")) {
        try {
            # Check if policy already exists
            $existing = Get-MgIdentityConditionalAccessPolicy -All | 
                Where-Object { $_.DisplayName -eq $policyName }
            
            if ($existing) {
                Write-Host "  [!] Emergency policy '$policyName' already exists - skipping" -ForegroundColor Yellow
                return $existing
            }
            
            $created = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy -ErrorAction Stop
            Write-Host "  [✓] Created emergency policy: $Name" -ForegroundColor Green
            Write-Host "      Policy name: $policyName" -ForegroundColor Gray
            Write-Host "      Description: $Description" -ForegroundColor Gray
            return $created
        }
        catch {
            Write-Error "Failed to create emergency policy '$policyName': $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create emergency policy: $policyName" -ForegroundColor Yellow
        return $policy
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Emergency CA Policies Creation" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.ConditionalAccess.Enabled) {
        Write-Warning "Conditional Access is disabled in configuration. Exiting."
        return
    }
    
    if (-not $config.ConditionalAccess.EmergencyPolicies.Create) {
        Write-Warning "Emergency policies creation is disabled in configuration. Exiting."
        return
    }
    
    # Verify Graph connection
    $context = Get-MgContext
    if (-not $context) {
        Write-Error "Not connected to Microsoft Graph. Run Connect-EntraID.ps1 first."
        return
    }
    
    Write-Host "`nConfiguration:" -ForegroundColor Cyan
    Write-Host "  Organization: $($config.OrganizationName)" -ForegroundColor Gray
    Write-Host "  Emergency policy prefix: $($config.ConditionalAccess.EmergencyPolicies.Prefix)" -ForegroundColor Gray
    
    # Capture current state
    Write-Host "`nCapturing existing Conditional Access policies..." -ForegroundColor Cyan
    $existingPolicies = Get-MgIdentityConditionalAccessPolicy -All
    
    # Define emergency policies
    $emergencyPolicies = @()
    $policyCount = 1
    $totalPolicies = 4
    
    # Emergency Policy 1: MFA Disruption - Allow access without MFA
    Write-Host "`nCreating emergency policies..." -ForegroundColor Cyan
    
    $policy1Conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    
    $policy1Grant = @{
        operator = "OR"
        builtInControls = @("block")
    }
    
    $policy1 = New-EmergencyPolicy `
        -Name "MFA Service Disruption" `
        -Description "Enable this if MFA service is unavailable. Allows sign-in without MFA. DISABLE AS SOON AS SERVICE IS RESTORED." `
        -Conditions $policy1Conditions `
        -GrantControls $policy1Grant `
        -PolicyNumber $policyCount `
        -TotalPolicies $totalPolicies
    
    if ($policy1) { $emergencyPolicies += $policy1 }
    $policyCount++
    
    # Emergency Policy 2: Trusted Location Only Access
    $policy2Conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        locations = @{
            includeLocations = @("All")
            excludeLocations = @("AllTrusted")
        }
        clientAppTypes = @("all")
    }
    
    $policy2Grant = @{
        operator = "OR"
        builtInControls = @("block")
    }
    
    $policy2 = New-EmergencyPolicy `
        -Name "Block All Non-Trusted Locations" `
        -Description "Enable during security incident to restrict access to trusted locations only." `
        -Conditions $policy2Conditions `
        -GrantControls $policy2Grant `
        -PolicyNumber $policyCount `
        -TotalPolicies $totalPolicies
    
    if ($policy2) { $emergencyPolicies += $policy2 }
    $policyCount++
    
    # Emergency Policy 3: Block All Access (Nuclear Option)
    $policy3Conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    
    $policy3Grant = @{
        operator = "OR"
        builtInControls = @("block")
    }
    
    $policy3 = New-EmergencyPolicy `
        -Name "Block All Access - NUCLEAR OPTION" `
        -Description "EXTREME EMERGENCY ONLY. Blocks all user access. Ensure break-glass accounts are excluded." `
        -Conditions $policy3Conditions `
        -GrantControls $policy3Grant `
        -PolicyNumber $policyCount `
        -TotalPolicies $totalPolicies
    
    if ($policy3) { $emergencyPolicies += $policy3 }
    $policyCount++
    
    # Emergency Policy 4: Compliant Device Bypass
    $policy4Conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    
    $policy4Grant = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
    
    $policy4 = New-EmergencyPolicy `
        -Name "Bypass Device Compliance" `
        -Description "Enable if Intune/device compliance service is disrupted. Requires MFA only (no device check)." `
        -Conditions $policy4Conditions `
        -GrantControls $policy4Grant `
        -PolicyNumber $policyCount `
        -TotalPolicies $totalPolicies
    
    if ($policy4) { $emergencyPolicies += $policy4 }
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles -and $emergencyPolicies.Count -gt 0) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "Emergency-CA-Policies" `
            -BeforeState $existingPolicies `
            -AfterState $emergencyPolicies `
            -ChangeDescription "Created emergency Conditional Access policies (disabled by default)"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Emergency Policies Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Emergency policies created: $($emergencyPolicies.Count)" -ForegroundColor Gray
    Write-Host "All policies are DISABLED by default" -ForegroundColor Yellow
    
    foreach ($policy in $emergencyPolicies) {
        $displayName = if ($policy.DisplayName) { $policy.DisplayName } else { $policy.displayName }
        Write-Host "  [✓] $displayName" -ForegroundColor Green
    }
    
    Write-Host "`n[IMPORTANT] Emergency Policy Procedures" -ForegroundColor Red
    Write-Host "=====================================" -ForegroundColor Red
    
    Write-Host "`n1. WHEN TO USE:" -ForegroundColor Yellow
    Write-Host "   - MFA service disruption affecting user access" -ForegroundColor Gray
    Write-Host "   - Security incident requiring immediate access lockdown" -ForegroundColor Gray
    Write-Host "   - Device compliance service outage" -ForegroundColor Gray
    Write-Host "   - Active security breach in progress" -ForegroundColor Gray
    
    Write-Host "`n2. HOW TO ENABLE:" -ForegroundColor Yellow
    Write-Host "   a. Navigate to: Entra ID > Security > Conditional Access" -ForegroundColor Gray
    Write-Host "   b. Find the appropriate EM## policy" -ForegroundColor Gray
    Write-Host "   c. Edit policy and change State to 'Enabled'" -ForegroundColor Gray
    Write-Host "   d. Document the activation (who, when, why)" -ForegroundColor Gray
    
    Write-Host "`n3. AFTER EMERGENCY:" -ForegroundColor Yellow
    Write-Host "   - Disable emergency policy as soon as possible" -ForegroundColor Gray
    Write-Host "   - Verify normal policies are functioning" -ForegroundColor Gray
    Write-Host "   - Conduct post-incident review" -ForegroundColor Gray
    Write-Host "   - Update emergency procedures if needed" -ForegroundColor Gray
    
    Write-Host "`n4. BREAK-GLASS ACCOUNTS:" -ForegroundColor Yellow
    Write-Host "   - Ensure break-glass accounts are excluded from ALL emergency policies" -ForegroundColor Gray
    Write-Host "   - Test emergency policy activation with break-glass account quarterly" -ForegroundColor Gray
    
    Write-Host "`n5. TESTING:" -ForegroundColor Yellow
    Write-Host "   - Test emergency procedures quarterly" -ForegroundColor Gray
    Write-Host "   - Use a test user account for validation" -ForegroundColor Gray
    Write-Host "   - Document test results and update procedures" -ForegroundColor Gray
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Document emergency policy activation procedures" -ForegroundColor Gray
    Write-Host "2. Train security team on when and how to use these policies" -ForegroundColor Gray
    Write-Host "3. Ensure break-glass accounts are properly excluded" -ForegroundColor Gray
    Write-Host "4. Schedule quarterly emergency procedure drills" -ForegroundColor Gray
    Write-Host "5. Create runbooks for common emergency scenarios" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Emergency policy creation failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

