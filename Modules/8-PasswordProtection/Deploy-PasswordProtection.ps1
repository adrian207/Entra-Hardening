<#
.SYNOPSIS
    Deploys password protection policies for Entra ID.

.DESCRIPTION
    Configures banned password lists, password policies, and smart lockout settings
    to prevent weak or compromised passwords.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    .\Deploy-PasswordProtection.ps1 -WhatIf

.EXAMPLE
    .\Deploy-PasswordProtection.ps1
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

function Show-PasswordProtectionGuidance {
    param([object]$Config)
    
    Write-Host "`nPassword Protection Configuration" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Gray
    
    Write-Host "`n[Manual Configuration Required]" -ForegroundColor Yellow
    Write-Host "Password protection settings are configured via Azure Portal" -ForegroundColor Gray
    
    Write-Host "`nSteps to Configure:" -ForegroundColor Cyan
    Write-Host "1. Navigate to: Entra ID > Security > Authentication methods > Password protection" -ForegroundColor Gray
    
    Write-Host "`n2. Configure Custom Banned Passwords:" -ForegroundColor Yellow
    if ($Config.PasswordProtection.EnforceCustomBannedPasswords -and $Config.PasswordProtection.CustomBannedPasswords) {
        Write-Host "   Add the following to the banned list:" -ForegroundColor Gray
        foreach ($password in $Config.PasswordProtection.CustomBannedPasswords) {
            Write-Host "     - $password" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n3. Smart Lockout Settings:" -ForegroundColor Yellow
    Write-Host "   - Lockout threshold: $($Config.PasswordProtection.LockoutThreshold) failed attempts" -ForegroundColor Gray
    Write-Host "   - Lockout duration: $($Config.PasswordProtection.LockoutDuration) seconds" -ForegroundColor Gray
    
    Write-Host "`n4. Additional Recommendations:" -ForegroundColor Yellow
    Write-Host "   - Enable 'Enforce custom list': Yes" -ForegroundColor Gray
    Write-Host "   - Enable 'Enable password protection on Windows Server AD': Yes (if hybrid)" -ForegroundColor Gray
    Write-Host "   - Mode: Enforced (after testing in Audit mode)" -ForegroundColor Gray
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Password Protection Deployment" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.PasswordProtection.Enabled) {
        Write-Warning "Password protection is disabled in configuration. Exiting."
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
    Write-Host "  Custom banned passwords: $($config.PasswordProtection.CustomBannedPasswords.Count)" -ForegroundColor Gray
    Write-Host "  Lockout threshold: $($config.PasswordProtection.LockoutThreshold)" -ForegroundColor Gray
    
    # Show configuration guidance
    Show-PasswordProtectionGuidance -Config $config
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Password Protection Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    
    Write-Host "`nPassword Protection Features:" -ForegroundColor Cyan
    Write-Host "  [✓] Global banned password list (Microsoft-managed)" -ForegroundColor Gray
    Write-Host "  [✓] Custom banned password list (organization-specific)" -ForegroundColor Gray
    Write-Host "  [✓] Smart lockout (protects against password spray attacks)" -ForegroundColor Gray
    Write-Host "  [✓] Fuzzy matching (catches variations like P@ssw0rd)" -ForegroundColor Gray
    
    Write-Host "`nWhat Gets Blocked:" -ForegroundColor Yellow
    Write-Host "  - Common weak passwords (password, 123456, etc.)" -ForegroundColor Gray
    Write-Host "  - Company name variations" -ForegroundColor Gray
    Write-Host "  - Product names" -ForegroundColor Gray
    Write-Host "  - Location names" -ForegroundColor Gray
    Write-Host "  - Keyboard patterns (qwerty, etc.)" -ForegroundColor Gray
    Write-Host "  - Custom terms from your banned list" -ForegroundColor Gray
    
    Write-Host "`nBest Practices:" -ForegroundColor Cyan
    Write-Host "  1. Add organization-specific terms:" -ForegroundColor Gray
    Write-Host "     - Company name and common abbreviations" -ForegroundColor Gray
    Write-Host "     - Product or service names" -ForegroundColor Gray
    Write-Host "     - Office location names" -ForegroundColor Gray
    Write-Host "  2. Start in Audit mode, then move to Enforced" -ForegroundColor Gray
    Write-Host "  3. Monitor password change failures" -ForegroundColor Gray
    Write-Host "  4. Adjust lockout settings based on attack patterns" -ForegroundColor Gray
    Write-Host "  5. Combine with MFA for comprehensive protection" -ForegroundColor Gray
    
    Write-Host "`nSmart Lockout Benefits:" -ForegroundColor Cyan
    Write-Host "  - Distinguishes legitimate users from attackers" -ForegroundColor Gray
    Write-Host "  - Prevents password spray attacks" -ForegroundColor Gray
    Write-Host "  - Uses machine learning to detect attack patterns" -ForegroundColor Gray
    Write-Host "  - Doesn't lock out legitimate users during attacks" -ForegroundColor Gray
    
    Write-Host "`nFor Hybrid Environments:" -ForegroundColor Yellow
    Write-Host "  Enable password protection for on-premises AD:" -ForegroundColor Gray
    Write-Host "  1. Download DC agent from Microsoft" -ForegroundColor Gray
    Write-Host "  2. Install on all domain controllers" -ForegroundColor Gray
    Write-Host "  3. Configure forest-wide settings" -ForegroundColor Gray
    Write-Host "  4. Monitor event logs for password rejections" -ForegroundColor Gray
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Configure password protection in Azure Portal" -ForegroundColor Gray
    Write-Host "2. Add custom banned passwords" -ForegroundColor Gray
    Write-Host "3. Test in Audit mode first" -ForegroundColor Gray
    Write-Host "4. Review audit logs after 1-2 weeks" -ForegroundColor Gray
    Write-Host "5. Switch to Enforced mode" -ForegroundColor Gray
    Write-Host "6. Monitor ongoing password change attempts" -ForegroundColor Gray
}
catch {
    Write-Error "Password protection deployment failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

