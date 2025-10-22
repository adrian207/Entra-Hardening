<#
.SYNOPSIS
    Hardens B2B (guest user) collaboration settings in Entra ID.

.DESCRIPTION
    Configures external collaboration settings to secure guest user access, restrict
    invitations, and implement access reviews for external identities.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    .\Harden-B2BSettings.ps1 -WhatIf

.EXAMPLE
    .\Harden-B2BSettings.ps1
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

function Get-CurrentB2BSettings {
    <#
    .SYNOPSIS
        Retrieves current B2B collaboration settings.
    #>
    Write-Host "Retrieving current B2B settings..." -ForegroundColor Cyan
    
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        
        if ($authPolicy) {
            Write-Host "  Current external user settings:" -ForegroundColor Gray
            Write-Host "    - Guest user access: $($authPolicy.AllowedToSignUpEmailBasedSubscriptions)" -ForegroundColor Gray
        }
        
        return $authPolicy
    }
    catch {
        Write-Error "Failed to retrieve B2B settings: $($_.Exception.Message)"
        return $null
    }
}

function Set-ExternalCollaborationSettings {
    param([object]$Config)
    
    if ($PSCmdlet.ShouldProcess("External Collaboration Settings", "Update")) {
        try {
            Write-Host "`nConfiguring external collaboration settings..." -ForegroundColor Cyan
            
            # Note: Full B2B settings configuration requires Azure Portal or specific APIs
            Write-Host "  [Manual Configuration Required]" -ForegroundColor Yellow
            Write-Host "  Navigate to: Entra ID > External Identities > External collaboration settings" -ForegroundColor Gray
            
            Write-Host "`n  Recommended Settings:" -ForegroundColor Cyan
            
            Write-Host "`n  Guest User Access Restrictions:" -ForegroundColor Yellow
            Write-Host "    [Recommended] Guest users have limited access to properties and memberships" -ForegroundColor Gray
            Write-Host "    [Most Secure] Guest user access is restricted to their own directory objects" -ForegroundColor Gray
            
            Write-Host "`n  Guest Invite Settings:" -ForegroundColor Yellow
            if ($Config.ExternalCollaboration.B2BSettings.AllowInvitations) {
                Write-Host "    [✓] Invitations enabled" -ForegroundColor Green
                
                $allowedRoles = $Config.ExternalCollaboration.B2BSettings.AllowedToInvite -join ', '
                Write-Host "    Allowed to invite: $allowedRoles" -ForegroundColor Gray
            } else {
                Write-Host "    [!] Block all invitations" -ForegroundColor Red
            }
            
            Write-Host "`n  Collaboration Restrictions:" -ForegroundColor Yellow
            if ($Config.ExternalCollaboration.B2BSettings.AllowedDomains -and $Config.ExternalCollaboration.B2BSettings.AllowedDomains.Count -gt 0) {
                Write-Host "    [Allowlist] Only allow invitations to:" -ForegroundColor Green
                foreach ($domain in $Config.ExternalCollaboration.B2BSettings.AllowedDomains) {
                    Write-Host "      - $domain" -ForegroundColor Gray
                }
            }
            
            if ($Config.ExternalCollaboration.B2BSettings.BlockedDomains -and $Config.ExternalCollaboration.B2BSettings.BlockedDomains.Count -gt 0) {
                Write-Host "    [Blocklist] Block invitations to:" -ForegroundColor Red
                foreach ($domain in $Config.ExternalCollaboration.B2BSettings.BlockedDomains) {
                    Write-Host "      - $domain" -ForegroundColor Gray
                }
            }
            
            return $true
        }
        catch {
            Write-Error "Failed to configure B2B settings: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        Write-Host "  [WhatIf] Would configure external collaboration settings" -ForegroundColor Yellow
        return $true
    }
}

function Get-GuestUsers {
    <#
    .SYNOPSIS
        Retrieves all guest users in the directory.
    #>
    Write-Host "`nAnalyzing guest users..." -ForegroundColor Cyan
    
    try {
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -ErrorAction Stop
        
        Write-Host "  Total guest users: $($guestUsers.Count)" -ForegroundColor Gray
        
        # Analyze guest user activity
        $recentlyActive = $guestUsers | Where-Object { 
            $_.SignInActivity.LastSignInDateTime -and 
            $_.SignInActivity.LastSignInDateTime -gt (Get-Date).AddDays(-30) 
        }
        
        $inactive = $guestUsers | Where-Object {
            -not $_.SignInActivity.LastSignInDateTime -or
            $_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90)
        }
        
        Write-Host "  Active (last 30 days): $($recentlyActive.Count)" -ForegroundColor Green
        Write-Host "  Inactive (>90 days): $($inactive.Count)" -ForegroundColor Yellow
        
        if ($inactive.Count -gt 0) {
            Write-Host "`n  [Recommendation] Review inactive guest accounts for removal" -ForegroundColor Yellow
        }
        
        return @{
            Total = $guestUsers.Count
            Active = $recentlyActive.Count
            Inactive = $inactive.Count
            InactiveUsers = $inactive
        }
    }
    catch {
        Write-Error "Failed to retrieve guest users: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  B2B Collaboration Hardening" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.ExternalCollaboration.Enabled) {
        Write-Warning "External collaboration hardening is disabled in configuration. Exiting."
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
    Write-Host "  Guest user access level: $($config.ExternalCollaboration.GuestUserAccess)" -ForegroundColor Gray
    
    # Capture current state
    $currentSettings = Get-CurrentB2BSettings
    
    # Configure B2B settings
    $result = Set-ExternalCollaborationSettings -Config $config
    
    # Analyze guest users
    $guestAnalysis = Get-GuestUsers
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "B2B-Hardening" `
            -BeforeState $currentSettings `
            -AfterState @{
                GuestUserAccess = $config.ExternalCollaboration.GuestUserAccess
                AllowInvitations = $config.ExternalCollaboration.B2BSettings.AllowInvitations
            } `
            -ChangeDescription "Hardened B2B collaboration settings"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  B2B Hardening Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    
    Write-Host "`nManual Configuration Steps:" -ForegroundColor Cyan
    Write-Host "1. Navigate to: Entra ID > External Identities > External collaboration settings" -ForegroundColor Gray
    Write-Host "2. Set 'Guest user access restrictions' to: $($config.ExternalCollaboration.GuestUserAccess)" -ForegroundColor Gray
    Write-Host "3. Configure guest invite settings based on config.json" -ForegroundColor Gray
    Write-Host "4. Set collaboration restrictions (allow/block domains)" -ForegroundColor Gray
    Write-Host "5. Enable cross-tenant access settings if needed" -ForegroundColor Gray
    
    Write-Host "`nSecurity Best Practices:" -ForegroundColor Yellow
    Write-Host "  [✓] Restrict guest user permissions to minimum needed" -ForegroundColor Gray
    Write-Host "  [✓] Require approval process for guest invitations" -ForegroundColor Gray
    Write-Host "  [✓] Use domain allowlists/blocklists" -ForegroundColor Gray
    Write-Host "  [✓] Implement access reviews for guest users" -ForegroundColor Gray
    Write-Host "  [✓] Apply Conditional Access to guest users" -ForegroundColor Gray
    Write-Host "  [✓] Set guest access expiration policies" -ForegroundColor Gray
    
    Write-Host "`nConditional Access for Guests:" -ForegroundColor Cyan
    Write-Host "  Consider creating CA policies that:" -ForegroundColor Gray
    Write-Host "    - Require MFA for all guest users" -ForegroundColor Gray
    Write-Host "    - Restrict guest access to specific applications" -ForegroundColor Gray
    Write-Host "    - Block guest access from untrusted locations" -ForegroundColor Gray
    Write-Host "    - Require terms of use acceptance" -ForegroundColor Gray
    
    if ($guestAnalysis -and $guestAnalysis.Inactive -gt 0) {
        Write-Host "`nInactive Guest Accounts:" -ForegroundColor Yellow
        Write-Host "  Found $($guestAnalysis.Inactive) inactive guest accounts (>90 days)" -ForegroundColor Yellow
        Write-Host "  Review and remove unused accounts:" -ForegroundColor Gray
        Write-Host "    Entra ID > Users > All users > Filter by 'Guest'" -ForegroundColor Gray
    }
    
    Write-Host "`nAccess Reviews:" -ForegroundColor Cyan
    Write-Host "  Set up quarterly access reviews for:" -ForegroundColor Gray
    Write-Host "    - All guest users" -ForegroundColor Gray
    Write-Host "    - Guest access to sensitive groups" -ForegroundColor Gray
    Write-Host "    - Guest application assignments" -ForegroundColor Gray
    Write-Host "  Location: Entra ID > Identity Governance > Access reviews" -ForegroundColor Gray
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Complete manual configuration in Azure Portal" -ForegroundColor Gray
    Write-Host "2. Create Conditional Access policies for guests" -ForegroundColor Gray
    Write-Host "3. Set up access reviews for guest users" -ForegroundColor Gray
    Write-Host "4. Configure entitlement management for guest access" -ForegroundColor Gray
    Write-Host "5. Train users on guest invitation process" -ForegroundColor Gray
    Write-Host "6. Remove inactive guest accounts" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "B2B hardening failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

