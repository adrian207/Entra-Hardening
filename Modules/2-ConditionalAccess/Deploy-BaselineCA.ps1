<#
.SYNOPSIS
    Deploys baseline Conditional Access policies for Entra ID hardening.

.DESCRIPTION
    Creates a comprehensive set of baseline Conditional Access policies based on Microsoft
    security best practices. Policies are deployed in report-only mode by default.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.PARAMETER EnforceImmediately
    Skip report-only mode and enforce policies immediately.

.PARAMETER PolicyName
    Deploy a specific baseline policy instead of all policies.

.EXAMPLE
    .\Deploy-BaselineCA.ps1 -WhatIf

.EXAMPLE
    .\Deploy-BaselineCA.ps1

.EXAMPLE
    .\Deploy-BaselineCA.ps1 -EnforceImmediately

.EXAMPLE
    .\Deploy-BaselineCA.ps1 -PolicyName "RequireMFAForAdmins"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnforceImmediately,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet(
        'RequireMFAForAllUsers',
        'RequireMFAForAdmins',
        'RequireMFAForAzureManagement',
        'BlockLegacyAuth',
        'RequireCompliantDeviceForAdmins',
        'BlockHighRiskSignIns',
        'RequirePasswordChangeForHighRiskUsers',
        'All'
    )]
    [string]$PolicyName = 'All'
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function Get-AdminRoleTemplateIds {
    <#
    .SYNOPSIS
        Returns a hashtable of common admin role template IDs.
    #>
    return @{
        'GlobalAdministrator' = '62e90394-69f5-4237-9190-012177145e10'
        'SecurityAdministrator' = '194ae4cb-b126-40b2-bd5b-6091b380977d'
        'SharePointAdministrator' = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
        'ExchangeAdministrator' = '29232cdf-9323-42fd-ade2-1d097af3e4de'
        'ConditionalAccessAdministrator' = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'
        'HelpdeskAdministrator' = '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        'BillingAdministrator' = 'b0f54661-2d74-4c50-afa3-1ec803f12efe'
        'UserAdministrator' = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        'ApplicationAdministrator' = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        'CloudApplicationAdministrator' = 'cf1c38e5-3621-4004-a7cb-879624dced7c'
        'PrivilegedAuthenticationAdministrator' = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        'AuthenticationAdministrator' = 'c4e39bd9-1100-46d3-8c65-fb160da0071f'
        'PrivilegedRoleAdministrator' = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        'ComplianceAdministrator' = '17315797-102d-40b4-93e0-432062caca18'
        'IntuneAdministrator' = '3a2c62db-5318-420d-8d74-23affee5d9d5'
    }
}

function New-CAPolicy {
    param(
        [string]$DisplayName,
        [object]$Conditions,
        [object]$GrantControls,
        [object]$SessionControls = $null,
        [bool]$ReportOnly = $true,
        [string[]]$ExcludeUsers = @(),
        [string[]]$ExcludeGroups = @()
    )
    
    $state = if ($ReportOnly) { "enabledForReportingButNotEnforced" } else { "enabled" }
    
    # Add exclusions to conditions
    if ($ExcludeUsers.Count -gt 0) {
        $Conditions.users.excludeUsers = $ExcludeUsers
    }
    if ($ExcludeGroups.Count -gt 0) {
        $Conditions.users.excludeGroups = $ExcludeGroups
    }
    
    $policy = @{
        displayName = $DisplayName
        state = $state
        conditions = $Conditions
        grantControls = $GrantControls
    }
    
    if ($SessionControls) {
        $policy.sessionControls = $SessionControls
    }
    
    if ($PSCmdlet.ShouldProcess($DisplayName, "Create Conditional Access Policy")) {
        try {
            # Check if policy already exists
            $existing = Get-MgIdentityConditionalAccessPolicy -All | 
                Where-Object { $_.DisplayName -eq $DisplayName }
            
            if ($existing) {
                Write-Host "  [!] Policy '$DisplayName' already exists - skipping" -ForegroundColor Yellow
                return $existing
            }
            
            $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy -ErrorAction Stop
            Write-Host "  [✓] Created: $DisplayName" -ForegroundColor Green
            return $createdPolicy
        }
        catch {
            Write-Error "Failed to create policy '$DisplayName': $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create: $DisplayName (State: $state)" -ForegroundColor Yellow
        return $policy
    }
}

function New-RequireMFAForAllUsersPolicy {
    param([bool]$ReportOnly, [string[]]$ExcludeUsers, [string[]]$ExcludeGroups)
    
    $conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    
    $grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
    
    return New-CAPolicy `
        -DisplayName "BASELINE: Require MFA for All Users" `
        -Conditions $conditions `
        -GrantControls $grantControls `
        -ReportOnly $ReportOnly `
        -ExcludeUsers $ExcludeUsers `
        -ExcludeGroups $ExcludeGroups
}

function New-RequireMFAForAdminsPolicy {
    param([bool]$ReportOnly, [string[]]$ExcludeUsers, [string[]]$ExcludeGroups)
    
    $adminRoles = Get-AdminRoleTemplateIds
    
    $conditions = @{
        users = @{
            includeRoles = $adminRoles.Values
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    
    $grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
    
    return New-CAPolicy `
        -DisplayName "BASELINE: Require MFA for Administrators" `
        -Conditions $conditions `
        -GrantControls $grantControls `
        -ReportOnly $ReportOnly `
        -ExcludeUsers $ExcludeUsers `
        -ExcludeGroups $ExcludeGroups
}

function New-RequireMFAForAzureManagementPolicy {
    param([bool]$ReportOnly, [string[]]$ExcludeUsers, [string[]]$ExcludeGroups)
    
    # Azure Management app ID
    $azureManagementAppId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
    
    $conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @($azureManagementAppId)
        }
        clientAppTypes = @("all")
    }
    
    $grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
    
    return New-CAPolicy `
        -DisplayName "BASELINE: Require MFA for Azure Management" `
        -Conditions $conditions `
        -GrantControls $grantControls `
        -ReportOnly $ReportOnly `
        -ExcludeUsers $ExcludeUsers `
        -ExcludeGroups $ExcludeGroups
}

function New-RequireCompliantDeviceForAdminsPolicy {
    param([bool]$ReportOnly, [string[]]$ExcludeUsers, [string[]]$ExcludeGroups)
    
    $adminRoles = Get-AdminRoleTemplateIds
    
    $conditions = @{
        users = @{
            includeRoles = $adminRoles.Values
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
        platforms = @{
            includePlatforms = @("all")
        }
    }
    
    $grantControls = @{
        operator = "OR"
        builtInControls = @("compliantDevice", "domainJoinedDevice")
    }
    
    return New-CAPolicy `
        -DisplayName "BASELINE: Require Compliant or Hybrid Joined Device for Admins" `
        -Conditions $conditions `
        -GrantControls $grantControls `
        -ReportOnly $ReportOnly `
        -ExcludeUsers $ExcludeUsers `
        -ExcludeGroups $ExcludeGroups
}

function New-BlockHighRiskSignInsPolicy {
    param([bool]$ReportOnly, [string[]]$ExcludeUsers, [string[]]$ExcludeGroups)
    
    $conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        signInRiskLevels = @("high")
        clientAppTypes = @("all")
    }
    
    $grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
    
    return New-CAPolicy `
        -DisplayName "BASELINE: Block High Risk Sign-ins" `
        -Conditions $conditions `
        -GrantControls $grantControls `
        -ReportOnly $ReportOnly `
        -ExcludeUsers $ExcludeUsers `
        -ExcludeGroups $ExcludeGroups
}

function New-RequirePasswordChangeForHighRiskUsersPolicy {
    param([bool]$ReportOnly, [string[]]$ExcludeUsers, [string[]]$ExcludeGroups)
    
    $conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        userRiskLevels = @("high")
        clientAppTypes = @("all")
    }
    
    $grantControls = @{
        operator = "AND"
        builtInControls = @("mfa", "passwordChange")
    }
    
    return New-CAPolicy `
        -DisplayName "BASELINE: Require Password Change for High Risk Users" `
        -Conditions $conditions `
        -GrantControls $grantControls `
        -ReportOnly $ReportOnly `
        -ExcludeUsers $ExcludeUsers `
        -ExcludeGroups $ExcludeGroups
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Baseline Conditional Access Deployment" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.ConditionalAccess.Enabled) {
        Write-Warning "Conditional Access is disabled in configuration. Exiting."
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
    Write-Host "  Report-only duration: $($config.ConditionalAccess.ReportOnlyDuration) days" -ForegroundColor Gray
    Write-Host "  Policy to deploy: $PolicyName" -ForegroundColor Gray
    
    # Capture current state
    Write-Host "`nCapturing existing Conditional Access policies..." -ForegroundColor Cyan
    $existingPolicies = Get-MgIdentityConditionalAccessPolicy -All
    Write-Host "  Found $($existingPolicies.Count) existing policies" -ForegroundColor Gray
    
    # Determine exclusions
    $excludeUsers = @()
    $excludeGroups = @()
    
    if ($config.ConditionalAccess.ExcludedUsers) {
        $excludeUsers += $config.ConditionalAccess.ExcludedUsers
    }
    
    if ($config.ConditionalAccess.ExcludedGroups) {
        $excludeGroups += $config.ConditionalAccess.ExcludedGroups
    }
    
    # Determine if report-only mode
    $useReportOnly = -not $EnforceImmediately
    
    # Create policies
    Write-Host "`nDeploying baseline Conditional Access policies..." -ForegroundColor Cyan
    $createdPolicies = @()
    
    if ($PolicyName -eq 'All' -or $PolicyName -eq 'RequireMFAForAllUsers') {
        if ($config.ConditionalAccess.BaselinePolicies.RequireMFAForAllUsers) {
            $policy = New-RequireMFAForAllUsersPolicy -ReportOnly $useReportOnly -ExcludeUsers $excludeUsers -ExcludeGroups $excludeGroups
            if ($policy) { $createdPolicies += $policy }
        }
    }
    
    if ($PolicyName -eq 'All' -or $PolicyName -eq 'RequireMFAForAdmins') {
        if ($config.ConditionalAccess.BaselinePolicies.RequireMFAForAdmins) {
            $policy = New-RequireMFAForAdminsPolicy -ReportOnly $useReportOnly -ExcludeUsers $excludeUsers -ExcludeGroups $excludeGroups
            if ($policy) { $createdPolicies += $policy }
        }
    }
    
    if ($PolicyName -eq 'All' -or $PolicyName -eq 'RequireMFAForAzureManagement') {
        if ($config.ConditionalAccess.BaselinePolicies.RequireMFAForAzureManagement) {
            $policy = New-RequireMFAForAzureManagementPolicy -ReportOnly $useReportOnly -ExcludeUsers $excludeUsers -ExcludeGroups $excludeGroups
            if ($policy) { $createdPolicies += $policy }
        }
    }
    
    if ($PolicyName -eq 'All' -or $PolicyName -eq 'RequireCompliantDeviceForAdmins') {
        if ($config.ConditionalAccess.BaselinePolicies.RequireCompliantDeviceForAdmins) {
            $policy = New-RequireCompliantDeviceForAdminsPolicy -ReportOnly $useReportOnly -ExcludeUsers $excludeUsers -ExcludeGroups $excludeGroups
            if ($policy) { $createdPolicies += $policy }
        }
    }
    
    if ($PolicyName -eq 'All' -or $PolicyName -eq 'BlockHighRiskSignIns') {
        if ($config.ConditionalAccess.BaselinePolicies.BlockHighRiskSignIns) {
            Write-Host "`n  [Note] High-risk sign-in blocking requires Entra ID P2 license" -ForegroundColor Yellow
            $policy = New-BlockHighRiskSignInsPolicy -ReportOnly $useReportOnly -ExcludeUsers $excludeUsers -ExcludeGroups $excludeGroups
            if ($policy) { $createdPolicies += $policy }
        }
    }
    
    if ($PolicyName -eq 'All' -or $PolicyName -eq 'RequirePasswordChangeForHighRiskUsers') {
        if ($config.ConditionalAccess.BaselinePolicies.RequirePasswordChangeForHighRiskUsers) {
            Write-Host "`n  [Note] Risk-based user policies require Entra ID P2 license" -ForegroundColor Yellow
            $policy = New-RequirePasswordChangeForHighRiskUsersPolicy -ReportOnly $useReportOnly -ExcludeUsers $excludeUsers -ExcludeGroups $excludeGroups
            if ($policy) { $createdPolicies += $policy }
        }
    }
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles -and $createdPolicies.Count -gt 0) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "Baseline-CA" `
            -BeforeState $existingPolicies `
            -AfterState $createdPolicies `
            -ChangeDescription "Deployed baseline Conditional Access policies"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Deployment Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Policies deployed: $($createdPolicies.Count)" -ForegroundColor Gray
    
    foreach ($policy in $createdPolicies) {
        $displayName = if ($policy.DisplayName) { $policy.DisplayName } else { $policy.displayName }
        Write-Host "  [✓] $displayName" -ForegroundColor Green
    }
    
    if ($useReportOnly) {
        Write-Host "`nMode: REPORT-ONLY" -ForegroundColor Yellow
        Write-Host "Monitor for $($config.ConditionalAccess.ReportOnlyDuration) days before enforcement." -ForegroundColor Yellow
        Write-Host "`nNext Steps:" -ForegroundColor Cyan
        Write-Host "1. Navigate to: Entra ID > Security > Conditional Access > Insights and reporting" -ForegroundColor Gray
        Write-Host "2. Review policy impact and user experience" -ForegroundColor Gray
        Write-Host "3. Address any issues or exclusions needed" -ForegroundColor Gray
        Write-Host "4. Re-run with -EnforceImmediately to activate policies" -ForegroundColor Gray
    }
    else {
        Write-Host "`nMode: ENFORCED" -ForegroundColor Green
        Write-Host "Baseline Conditional Access policies are now active!" -ForegroundColor Green
        Write-Host "`nMonitoring:" -ForegroundColor Cyan
        Write-Host "1. Monitor sign-in logs for policy effects" -ForegroundColor Gray
        Write-Host "2. Review user feedback and support tickets" -ForegroundColor Gray
        Write-Host "3. Adjust exclusions as needed (minimize over time)" -ForegroundColor Gray
        Write-Host "4. Regularly audit policy compliance" -ForegroundColor Gray
    }
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Baseline CA deployment failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

