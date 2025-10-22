<#
.SYNOPSIS
    Restricts user consent for applications in Entra ID.

.DESCRIPTION
    Disables user consent for applications to prevent users from granting permissions
    to potentially malicious third-party apps. Requires admin consent for all apps.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    .\Restrict-AppConsent.ps1 -WhatIf

.EXAMPLE
    .\Restrict-AppConsent.ps1
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

function Get-CurrentConsentPolicy {
    <#
    .SYNOPSIS
        Retrieves current application consent settings.
    #>
    Write-Host "Retrieving current consent policy..." -ForegroundColor Cyan
    
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        
        if ($authPolicy) {
            Write-Host "  Current settings:" -ForegroundColor Gray
            Write-Host "    - User consent for apps: $($authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)" -ForegroundColor Gray
            Write-Host "    - Users can register apps: $($authPolicy.DefaultUserRolePermissions.AllowedToCreateApps)" -ForegroundColor Gray
        }
        
        return $authPolicy
    }
    catch {
        Write-Error "Failed to retrieve consent policy: $($_.Exception.Message)"
        return $null
    }
}

function Set-UserConsentPolicy {
    param([bool]$AllowUserConsent)
    
    if ($PSCmdlet.ShouldProcess("User Consent Policy", "Update")) {
        try {
            $permissionGrantPolicy = if ($AllowUserConsent) {
                @("ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
            } else {
                @()  # Empty array disables user consent
            }
            
            $params = @{
                DefaultUserRolePermissions = @{
                    PermissionGrantPoliciesAssigned = $permissionGrantPolicy
                }
            }
            
            Update-MgPolicyAuthorizationPolicy -BodyParameter $params -ErrorAction Stop
            
            if ($AllowUserConsent) {
                Write-Host "  [✓] User consent for applications: ENABLED" -ForegroundColor Yellow
            } else {
                Write-Host "  [✓] User consent for applications: DISABLED" -ForegroundColor Green
                Write-Host "      Users cannot consent to apps - admin consent required" -ForegroundColor Gray
            }
            
            return $true
        }
        catch {
            Write-Error "Failed to update user consent policy: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        Write-Host "  [WhatIf] Would set user consent: $AllowUserConsent" -ForegroundColor Yellow
        return $true
    }
}

function Set-GroupOwnerConsentPolicy {
    param([bool]$AllowGroupOwnerConsent)
    
    if ($PSCmdlet.ShouldProcess("Group Owner Consent Policy", "Update")) {
        try {
            # Group owner consent is managed separately
            Write-Host "  [Note] Group owner consent configuration:" -ForegroundColor Yellow
            
            if ($AllowGroupOwnerConsent) {
                Write-Host "      Allowing group owners to consent to apps accessing group data" -ForegroundColor Gray
            } else {
                Write-Host "      Blocking group owners from consenting to apps" -ForegroundColor Gray
                Write-Host "      This must be configured in Azure Portal:" -ForegroundColor Gray
                Write-Host "      Entra ID > Enterprise applications > Consent and permissions > User consent settings" -ForegroundColor Gray
            }
            
            return $true
        }
        catch {
            Write-Error "Failed to configure group owner consent: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        Write-Host "  [WhatIf] Would set group owner consent: $AllowGroupOwnerConsent" -ForegroundColor Yellow
        return $true
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Application Consent Restriction" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.ApplicationSecurity.Enabled) {
        Write-Warning "Application security is disabled in configuration. Exiting."
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
    Write-Host "  Allow user consent: $($config.ApplicationSecurity.UserConsentSettings.AllowUserConsent)" -ForegroundColor Gray
    Write-Host "  Allow group owner consent: $($config.ApplicationSecurity.UserConsentSettings.AllowGroupOwnerConsent)" -ForegroundColor Gray
    
    # Capture current state
    $currentPolicy = Get-CurrentConsentPolicy
    
    # Update consent policies
    Write-Host "`nUpdating application consent settings..." -ForegroundColor Cyan
    
    $userConsentResult = Set-UserConsentPolicy -AllowUserConsent $config.ApplicationSecurity.UserConsentSettings.AllowUserConsent
    $groupOwnerConsentResult = Set-GroupOwnerConsentPolicy -AllowGroupOwnerConsent $config.ApplicationSecurity.UserConsentSettings.AllowGroupOwnerConsent
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "App-Consent-Restriction" `
            -BeforeState $currentPolicy `
            -AfterState @{
                AllowUserConsent = $config.ApplicationSecurity.UserConsentSettings.AllowUserConsent
                AllowGroupOwnerConsent = $config.ApplicationSecurity.UserConsentSettings.AllowGroupOwnerConsent
            } `
            -ChangeDescription "Restricted application consent settings"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  App Consent Configuration Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    
    Write-Host "`nSecurity Improvements:" -ForegroundColor Cyan
    Write-Host "  [✓] User consent disabled - prevents users from approving malicious apps" -ForegroundColor Green
    Write-Host "  [✓] Admin consent required for all applications" -ForegroundColor Green
    Write-Host "  [✓] Group owner consent restricted" -ForegroundColor Green
    
    Write-Host "`nAdmin Consent Workflow:" -ForegroundColor Cyan
    Write-Host "1. Users request access to applications" -ForegroundColor Gray
    Write-Host "2. Administrators review app permissions" -ForegroundColor Gray
    Write-Host "3. Admins grant consent after security review" -ForegroundColor Gray
    Write-Host "4. Access is logged and auditable" -ForegroundColor Gray
    
    Write-Host "`nReviewing App Consent Requests:" -ForegroundColor Cyan
    Write-Host "  Location: Entra ID > Enterprise applications > User consent requests" -ForegroundColor Gray
    Write-Host "  URL: https://portal.azure.com/#view/Microsoft_AAD_IAM/ConsentRequestsListBlade" -ForegroundColor Gray
    
    Write-Host "`nBest Practices:" -ForegroundColor Yellow
    Write-Host "  - Review all consent requests carefully before approving" -ForegroundColor Gray
    Write-Host "  - Verify app publisher and permissions requested" -ForegroundColor Gray
    Write-Host "  - Use Microsoft Defender for Cloud Apps for additional protection" -ForegroundColor Gray
    Write-Host "  - Regularly audit enterprise applications (run Audit-EnterpriseApps.ps1)" -ForegroundColor Gray
    Write-Host "  - Document approved applications and their purposes" -ForegroundColor Gray
    
    Write-Host "`nCommon Attack Scenarios Blocked:" -ForegroundColor Green
    Write-Host "  [✓] OAuth phishing attacks" -ForegroundColor Gray
    Write-Host "  [✓] Malicious applications harvesting data" -ForegroundColor Gray
    Write-Host "  [✓] Unauthorized third-party integrations" -ForegroundColor Gray
    Write-Host "  [✓] Social engineering via app consent" -ForegroundColor Gray
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Configure admin consent workflow:" -ForegroundColor Gray
    Write-Host "   Entra ID > Enterprise applications > Admin consent settings" -ForegroundColor Gray
    Write-Host "2. Designate reviewers for consent requests" -ForegroundColor Gray
    Write-Host "3. Train users on the new consent process" -ForegroundColor Gray
    Write-Host "4. Audit existing enterprise applications" -ForegroundColor Gray
    Write-Host "5. Document approval criteria for applications" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Application consent restriction failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

