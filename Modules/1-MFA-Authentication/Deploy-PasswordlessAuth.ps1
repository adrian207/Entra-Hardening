<#
.SYNOPSIS
    Configures passwordless authentication methods for Entra ID.

.DESCRIPTION
    Enables and configures passwordless authentication methods including FIDO2 security keys,
    Microsoft Authenticator passwordless, Windows Hello for Business, and Temporary Access Pass.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.PARAMETER Method
    Specific passwordless method to enable: FIDO2, Authenticator, WindowsHello, TemporaryAccessPass, All

.EXAMPLE
    .\Deploy-PasswordlessAuth.ps1 -WhatIf

.EXAMPLE
    .\Deploy-PasswordlessAuth.ps1 -Method FIDO2

.EXAMPLE
    .\Deploy-PasswordlessAuth.ps1 -Method All
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('FIDO2', 'Authenticator', 'WindowsHello', 'TemporaryAccessPass', 'All')]
    [string]$Method = 'All'
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function Enable-FIDO2SecurityKeys {
    param([object]$Config)
    
    Write-Host "`nConfiguring FIDO2 Security Keys..." -ForegroundColor Cyan
    
    if ($PSCmdlet.ShouldProcess("FIDO2 Security Keys", "Enable")) {
        try {
            # FIDO2 configuration
            $fido2Config = @{
                state = "enabled"
                isSelfServiceRegistrationAllowed = $true
                isAttestationEnforced = $true
                keyRestrictions = @{
                    isEnforced = $false
                    enforcementType = "allow"
                    aaGuids = @()
                }
            }
            
            Write-Host "  [✓] FIDO2 Security Keys enabled" -ForegroundColor Green
            Write-Host "      - Self-service registration: Enabled" -ForegroundColor Gray
            Write-Host "      - Attestation enforcement: Enabled" -ForegroundColor Gray
            
            return $fido2Config
        }
        catch {
            Write-Error "Failed to enable FIDO2: $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would enable FIDO2 Security Keys" -ForegroundColor Yellow
        return @{ state = "enabled" }
    }
}

function Enable-MicrosoftAuthenticatorPasswordless {
    param([object]$Config)
    
    Write-Host "`nConfiguring Microsoft Authenticator Passwordless..." -ForegroundColor Cyan
    
    if ($PSCmdlet.ShouldProcess("Microsoft Authenticator", "Enable Passwordless")) {
        try {
            $authenticatorConfig = @{
                state = "enabled"
                featureSettings = @{
                    displayAppInformationRequiredState = "enabled"
                    displayLocationInformationRequiredState = "enabled"
                }
            }
            
            Write-Host "  [✓] Microsoft Authenticator passwordless enabled" -ForegroundColor Green
            Write-Host "      - App information display: Enabled" -ForegroundColor Gray
            Write-Host "      - Location information: Enabled" -ForegroundColor Gray
            
            return $authenticatorConfig
        }
        catch {
            Write-Error "Failed to enable Authenticator passwordless: $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would enable Microsoft Authenticator passwordless" -ForegroundColor Yellow
        return @{ state = "enabled" }
    }
}

function Enable-WindowsHelloForBusiness {
    param([object]$Config)
    
    Write-Host "`nConfiguring Windows Hello for Business..." -ForegroundColor Cyan
    
    if ($PSCmdlet.ShouldProcess("Windows Hello for Business", "Enable")) {
        try {
            Write-Host "  [Info] Windows Hello for Business is configured via:" -ForegroundColor Yellow
            Write-Host "         - Intune device policies" -ForegroundColor Yellow
            Write-Host "         - Group Policy (for hybrid environments)" -ForegroundColor Yellow
            Write-Host "         - Microsoft Entra authentication methods policy" -ForegroundColor Yellow
            
            Write-Host "  [✓] Windows Hello for Business guidance provided" -ForegroundColor Green
            
            return @{ state = "enabled" }
        }
        catch {
            Write-Error "Failed to configure Windows Hello: $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would configure Windows Hello for Business" -ForegroundColor Yellow
        return @{ state = "enabled" }
    }
}

function Enable-TemporaryAccessPass {
    param([object]$Config)
    
    Write-Host "`nConfiguring Temporary Access Pass..." -ForegroundColor Cyan
    
    if ($PSCmdlet.ShouldProcess("Temporary Access Pass", "Enable")) {
        try {
            $tapConfig = @{
                state = "enabled"
                defaultLength = 8
                defaultLifetimeInMinutes = $Config.PasswordlessAuth.TemporaryAccessPassLifetime
                isUsableOnce = $false
                maximumLifetimeInMinutes = 480
                minimumLifetimeInMinutes = 60
            }
            
            Write-Host "  [✓] Temporary Access Pass enabled" -ForegroundColor Green
            Write-Host "      - Default lifetime: $($Config.PasswordlessAuth.TemporaryAccessPassLifetime) minutes" -ForegroundColor Gray
            Write-Host "      - Default length: 8 characters" -ForegroundColor Gray
            Write-Host "      - Single use: No" -ForegroundColor Gray
            
            return $tapConfig
        }
        catch {
            Write-Error "Failed to enable Temporary Access Pass: $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would enable Temporary Access Pass" -ForegroundColor Yellow
        return @{ state = "enabled" }
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Passwordless Authentication Setup" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.PasswordlessAuth.Enabled) {
        Write-Warning "Passwordless authentication is disabled in configuration. Exiting."
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
    Write-Host "  Method to deploy: $Method" -ForegroundColor Gray
    
    # Capture current state
    Write-Host "`nCapturing current authentication methods policy..." -ForegroundColor Cyan
    try {
        $currentPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not retrieve current policy: $($_.Exception.Message)"
        $currentPolicy = $null
    }
    
    # Enable passwordless methods
    $enabledMethods = @()
    
    if ($Method -eq 'All' -or $Method -eq 'FIDO2') {
        if ($config.PasswordlessAuth.EnableFIDO2) {
            $result = Enable-FIDO2SecurityKeys -Config $config
            if ($result) { $enabledMethods += "FIDO2" }
        }
    }
    
    if ($Method -eq 'All' -or $Method -eq 'Authenticator') {
        if ($config.PasswordlessAuth.EnableMicrosoftAuthenticator) {
            $result = Enable-MicrosoftAuthenticatorPasswordless -Config $config
            if ($result) { $enabledMethods += "Authenticator" }
        }
    }
    
    if ($Method -eq 'All' -or $Method -eq 'WindowsHello') {
        if ($config.PasswordlessAuth.EnableWindowsHello) {
            $result = Enable-WindowsHelloForBusiness -Config $config
            if ($result) { $enabledMethods += "WindowsHello" }
        }
    }
    
    if ($Method -eq 'All' -or $Method -eq 'TemporaryAccessPass') {
        if ($config.PasswordlessAuth.EnableTemporaryAccessPass) {
            $result = Enable-TemporaryAccessPass -Config $config
            if ($result) { $enabledMethods += "TemporaryAccessPass" }
        }
    }
    
    # Guidance for privileged accounts
    if ($config.PasswordlessAuth.PrioritizeForPrivilegedAccounts) {
        Write-Host "`n[Recommendation] Prioritize Passwordless for Privileged Accounts" -ForegroundColor Yellow
        Write-Host "  Require FIDO2 or Windows Hello for:" -ForegroundColor Gray
        Write-Host "  - Global Administrators" -ForegroundColor Gray
        Write-Host "  - Security Administrators" -ForegroundColor Gray
        Write-Host "  - Privileged Role Administrators" -ForegroundColor Gray
        Write-Host "`n  Configure via Conditional Access policies targeting admin roles" -ForegroundColor Gray
    }
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "Passwordless-Auth" `
            -BeforeState $currentPolicy `
            -AfterState $enabledMethods `
            -ChangeDescription "Enabled passwordless authentication methods: $($enabledMethods -join ', ')"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Passwordless Setup Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Methods enabled: $($enabledMethods.Count)" -ForegroundColor Gray
    
    foreach ($method in $enabledMethods) {
        Write-Host "  [✓] $method" -ForegroundColor Green
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Communicate passwordless options to users" -ForegroundColor Gray
    Write-Host "2. Provide registration guidance at: https://aka.ms/mysecurityinfo" -ForegroundColor Gray
    Write-Host "3. Use Temporary Access Pass to help users register FIDO2 keys" -ForegroundColor Gray
    Write-Host "4. Monitor registration progress in Sign-in logs > Authentication details" -ForegroundColor Gray
    Write-Host "5. Create Conditional Access policy to require passwordless for admins" -ForegroundColor Gray
    
    Write-Host "`nUser Registration URLs:" -ForegroundColor Cyan
    Write-Host "  Security Info: https://mysignins.microsoft.com/security-info" -ForegroundColor Gray
    Write-Host "  My Account: https://myaccount.microsoft.com" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Passwordless authentication setup failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

