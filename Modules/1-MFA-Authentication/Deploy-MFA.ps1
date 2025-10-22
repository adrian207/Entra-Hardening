<#
.SYNOPSIS
    Deploys Multi-Factor Authentication (MFA) enforcement for Entra ID users.

.DESCRIPTION
    Configures MFA requirements based on the configuration file. Can enforce MFA for all users,
    administrators only, or specific groups. Supports gradual rollout with grace periods.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.PARAMETER EnforceImmediately
    Bypass grace period and enforce MFA immediately.

.PARAMETER AdminsOnly
    Only enforce MFA for administrative accounts (useful for phased rollout).

.EXAMPLE
    .\Deploy-MFA.ps1 -WhatIf

.EXAMPLE
    .\Deploy-MFA.ps1 -AdminsOnly

.EXAMPLE
    .\Deploy-MFA.ps1 -EnforceImmediately
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnforceImmediately,
    
    [Parameter(Mandatory = $false)]
    [switch]$AdminsOnly
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function Get-AdminUsers {
    <#
    .SYNOPSIS
        Retrieves all users with administrative role assignments.
    #>
    Write-Host "Identifying administrative users..." -ForegroundColor Cyan
    
    $adminRoleTemplateIds = @(
        '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', # SharePoint Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de', # Exchange Administrator
        '729827e3-9c14-49f7-bb1b-9608f156bbb8', # Helpdesk Administrator
        'b0f54661-2d74-4c50-afa3-1ec803f12efe', # Billing Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1', # User Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', # Application Administrator
        'cf1c38e5-3621-4004-a7cb-879624dced7c', # Cloud Application Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', # Privileged Authentication Administrator
        'c4e39bd9-1100-46d3-8c65-fb160da0071f'  # Authentication Administrator
    )
    
    $adminUsers = @()
    
    foreach ($roleId in $adminRoleTemplateIds) {
        try {
            $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId -All -ErrorAction SilentlyContinue
            
            foreach ($member in $roleMembers) {
                if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                    $adminUsers += $member.Id
                }
            }
        }
        catch {
            Write-Verbose "Could not query role $roleId : $($_.Exception.Message)"
        }
    }
    
    $uniqueAdmins = $adminUsers | Select-Object -Unique
    Write-Host "Found $($uniqueAdmins.Count) unique administrative users" -ForegroundColor Gray
    
    return $uniqueAdmins
}

function New-MFAConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Creates a Conditional Access policy to enforce MFA.
    #>
    param(
        [string]$PolicyName,
        [string[]]$IncludeUsers,
        [string[]]$ExcludeUsers,
        [string[]]$ExcludeGroups,
        [bool]$ReportOnly = $true
    )
    
    $state = if ($ReportOnly) { "enabledForReportingButNotEnforced" } else { "enabled" }
    
    $policy = @{
        displayName = $PolicyName
        state = $state
        conditions = @{
            users = @{
                includeUsers = $IncludeUsers
                excludeUsers = $ExcludeUsers
                excludeGroups = $ExcludeGroups
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes = @("all")
        }
        grantControls = @{
            operator = "OR"
            builtInControls = @("mfa")
        }
    }
    
    if ($PSCmdlet.ShouldProcess($PolicyName, "Create MFA Conditional Access Policy")) {
        try {
            $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy -ErrorAction Stop
            Write-Host "  [✓] Created policy: $PolicyName" -ForegroundColor Green
            return $createdPolicy
        }
        catch {
            Write-Error "Failed to create policy $PolicyName : $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create policy: $PolicyName (State: $state)" -ForegroundColor Yellow
        return $policy
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  MFA Deployment for Entra ID" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.MFA.Enabled) {
        Write-Warning "MFA is disabled in configuration. Exiting."
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
    Write-Host "  Enforce for all users: $($config.MFA.EnforceForAllUsers)" -ForegroundColor Gray
    Write-Host "  Enforce for admins: $($config.MFA.EnforceForAdmins)" -ForegroundColor Gray
    Write-Host "  Grace period: $($config.MFA.GracePeriodDays) days" -ForegroundColor Gray
    
    if ($AdminsOnly) {
        Write-Host "  Mode: Administrators Only" -ForegroundColor Yellow
    }
    elseif ($config.MFA.EnforceForAllUsers) {
        Write-Host "  Mode: All Users" -ForegroundColor Yellow
    }
    
    # Capture current state for rollback
    Write-Host "`nCapturing current Conditional Access policies..." -ForegroundColor Cyan
    $existingPolicies = Get-MgIdentityConditionalAccessPolicy -All
    
    # Identify admin users
    $adminUserIds = Get-AdminUsers
    
    # Determine exclusions
    $excludeUsers = @()
    $excludeGroups = @()
    
    if ($config.ConditionalAccess.ExcludedUsers) {
        $excludeUsers += $config.ConditionalAccess.ExcludedUsers
    }
    
    if ($config.ConditionalAccess.ExcludedGroups) {
        $excludeGroups += $config.ConditionalAccess.ExcludedGroups
    }
    
    # Determine if we should use report-only mode
    $useReportOnly = $true
    if ($EnforceImmediately) {
        $useReportOnly = $false
        Write-Warning "Immediate enforcement enabled - policies will be active immediately!"
    }
    elseif (-not $config.DeploymentSettings.WhatIfByDefault) {
        $useReportOnly = $false
    }
    
    # Create MFA policies
    Write-Host "`nCreating MFA Conditional Access Policies..." -ForegroundColor Cyan
    $createdPolicies = @()
    
    # Policy 1: MFA for Administrators
    if ($config.MFA.EnforceForAdmins) {
        $adminPolicy = New-MFAConditionalAccessPolicy `
            -PolicyName "HARDENING: Require MFA for Administrators" `
            -IncludeUsers $adminUserIds `
            -ExcludeUsers $excludeUsers `
            -ExcludeGroups $excludeGroups `
            -ReportOnly $useReportOnly
        
        if ($adminPolicy) {
            $createdPolicies += $adminPolicy
        }
    }
    
    # Policy 2: MFA for All Users (if not AdminsOnly mode)
    if ($config.MFA.EnforceForAllUsers -and -not $AdminsOnly) {
        $allUsersPolicy = New-MFAConditionalAccessPolicy `
            -PolicyName "HARDENING: Require MFA for All Users" `
            -IncludeUsers @("All") `
            -ExcludeUsers $excludeUsers `
            -ExcludeGroups $excludeGroups `
            -ReportOnly $useReportOnly
        
        if ($allUsersPolicy) {
            $createdPolicies += $allUsersPolicy
        }
    }
    
    # Configure authentication methods
    Write-Host "`nConfiguring authentication methods..." -ForegroundColor Cyan
    
    try {
        # Get current authentication methods policy
        $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
        
        if ($authMethodsPolicy) {
            Write-Host "  Current authentication methods policy retrieved" -ForegroundColor Gray
            
            # Note: Detailed authentication method configuration requires specific API calls
            # This is a placeholder for the configuration logic
            Write-Host "  [Info] Authentication method configuration should be done via Entra ID portal" -ForegroundColor Yellow
            Write-Host "         Recommended methods: Microsoft Authenticator, FIDO2, Windows Hello" -ForegroundColor Yellow
            Write-Host "         Consider blocking: SMS, Voice Call (less secure)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Could not retrieve authentication methods policy: $($_.Exception.Message)"
    }
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "MFA-Deployment" `
            -BeforeState $existingPolicies `
            -AfterState $createdPolicies `
            -ChangeDescription "Deployed MFA Conditional Access policies"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  MFA Deployment Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Policies created: $($createdPolicies.Count)" -ForegroundColor Gray
    
    if ($useReportOnly) {
        Write-Host "`nMode: REPORT-ONLY" -ForegroundColor Yellow
        Write-Host "Policies are not enforced yet. Review sign-in logs for $($config.ConditionalAccess.ReportOnlyDuration) days." -ForegroundColor Yellow
        Write-Host "After review, run with -EnforceImmediately to activate policies." -ForegroundColor Yellow
    }
    else {
        Write-Host "`nMode: ENFORCED" -ForegroundColor Green
        Write-Host "MFA is now required for targeted users." -ForegroundColor Green
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Monitor sign-in logs in Entra ID portal" -ForegroundColor Gray
    Write-Host "2. Ensure users have registered MFA methods" -ForegroundColor Gray
    Write-Host "3. Review Conditional Access > Insights and reporting" -ForegroundColor Gray
    Write-Host "4. Consider deploying passwordless authentication (Deploy-PasswordlessAuth.ps1)" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "MFA deployment failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

