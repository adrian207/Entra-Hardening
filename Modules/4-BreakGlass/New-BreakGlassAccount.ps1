<#
.SYNOPSIS
    Creates emergency break-glass administrator accounts for Entra ID.

.DESCRIPTION
    Creates cloud-only emergency access accounts with permanent Global Administrator role.
    These accounts are used to prevent lockouts and should be stored securely.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.PARAMETER OutputPasswordFile
    Output passwords to a file (NOT RECOMMENDED for production - use secure storage instead).

.EXAMPLE
    .\New-BreakGlassAccount.ps1 -WhatIf

.EXAMPLE
    .\New-BreakGlassAccount.ps1

.EXAMPLE
    .\New-BreakGlassAccount.ps1 -OutputPasswordFile
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$OutputPasswordFile
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function New-SecurePassword {
    param([int]$Length = 32)
    
    # Generate a strong random password
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?'
    $password = -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    
    # Ensure password meets complexity requirements
    if (-not ($password -cmatch '[a-z]' -and $password -cmatch '[A-Z]' -and $password -cmatch '[0-9]' -and $password -cmatch '[^a-zA-Z0-9]')) {
        # Retry if complexity not met
        return New-SecurePassword -Length $Length
    }
    
    return $password
}

function Split-Password {
    param(
        [string]$Password,
        [int]$Parts = 2
    )
    
    $partLength = [Math]::Ceiling($Password.Length / $Parts)
    $passwordParts = @()
    
    for ($i = 0; $i -lt $Parts; $i++) {
        $start = $i * $partLength
        $length = [Math]::Min($partLength, $Password.Length - $start)
        if ($length -gt 0) {
            $passwordParts += $Password.Substring($start, $length)
        }
    }
    
    return $passwordParts
}

function New-BreakGlassUser {
    param(
        [string]$UserPrincipalName,
        [string]$DisplayName,
        [string]$Password,
        [string]$TenantDomain
    )
    
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Create Break-Glass Account")) {
        try {
            # Check if user already exists
            $existing = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
            
            if ($existing) {
                Write-Host "  [!] Account '$UserPrincipalName' already exists - skipping creation" -ForegroundColor Yellow
                return $existing
            }
            
            # Create user
            $passwordProfile = @{
                Password = $Password
                ForceChangePasswordNextSignIn = $false
            }
            
            $userParams = @{
                UserPrincipalName = $UserPrincipalName
                DisplayName = $DisplayName
                MailNickname = $UserPrincipalName.Split('@')[0]
                AccountEnabled = $true
                PasswordProfile = $passwordProfile
                UsageLocation = "US"  # Required for licensing
                PasswordPolicies = "DisablePasswordExpiration"
            }
            
            $user = New-MgUser -BodyParameter $userParams -ErrorAction Stop
            Write-Host "  [✓] Created break-glass account: $UserPrincipalName" -ForegroundColor Green
            
            return $user
        }
        catch {
            Write-Error "Failed to create break-glass account '$UserPrincipalName': $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create break-glass account: $UserPrincipalName" -ForegroundColor Yellow
        return @{ UserPrincipalName = $UserPrincipalName; DisplayName = $DisplayName }
    }
}

function Grant-GlobalAdminRole {
    param(
        [string]$UserId,
        [string]$UserPrincipalName
    )
    
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Assign Global Administrator Role")) {
        try {
            # Get Global Administrator role
            $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq 'Global Administrator'" -ErrorAction Stop
            
            if (-not $roleDefinition) {
                throw "Global Administrator role not found"
            }
            
            # Check if already assigned
            $existingAssignment = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$UserId' and roleDefinitionId eq '$($roleDefinition.Id)'" -ErrorAction SilentlyContinue
            
            if ($existingAssignment) {
                Write-Host "      Global Administrator role already assigned" -ForegroundColor Gray
                return $existingAssignment
            }
            
            # Assign role (permanent active assignment for break-glass)
            $roleAssignment = @{
                PrincipalId = $UserId
                RoleDefinitionId = $roleDefinition.Id
                DirectoryScopeId = "/"
            }
            
            $assignment = New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $roleAssignment -ErrorAction Stop
            Write-Host "      [✓] Assigned Global Administrator role (permanent)" -ForegroundColor Green
            
            return $assignment
        }
        catch {
            Write-Error "Failed to assign Global Administrator role to '$UserPrincipalName': $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "      [WhatIf] Would assign Global Administrator role" -ForegroundColor Yellow
        return @{ RoleAssigned = "Global Administrator" }
    }
}

function New-BreakGlassSecurityGroup {
    param([string]$GroupName, [string]$Description)
    
    if ($PSCmdlet.ShouldProcess($GroupName, "Create Break-Glass Security Group")) {
        try {
            # Check if group exists
            $existing = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
            
            if ($existing) {
                Write-Host "  [!] Group '$GroupName' already exists" -ForegroundColor Yellow
                return $existing
            }
            
            # Create role-assignable security group
            $groupParams = @{
                DisplayName = $GroupName
                Description = $Description
                MailEnabled = $false
                MailNickname = ($GroupName -replace '[^a-zA-Z0-9]', '')
                SecurityEnabled = $true
                IsAssignableToRole = $true
            }
            
            $group = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop
            Write-Host "  [✓] Created break-glass security group: $GroupName" -ForegroundColor Green
            
            return $group
        }
        catch {
            Write-Error "Failed to create break-glass group: $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create break-glass security group: $GroupName" -ForegroundColor Yellow
        return @{ DisplayName = $GroupName }
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Break-Glass Account Creation" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.BreakGlassAccounts.Enabled) {
        Write-Warning "Break-glass accounts are disabled in configuration. Exiting."
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
    Write-Host "  Tenant Domain: $($config.TenantDomain)" -ForegroundColor Gray
    Write-Host "  Accounts to create: $($config.BreakGlassAccounts.Count)" -ForegroundColor Gray
    Write-Host "  Password length: $($config.BreakGlassAccounts.PasswordLength) characters" -ForegroundColor Gray
    
    # Create break-glass security group
    Write-Host "`nCreating break-glass security group..." -ForegroundColor Cyan
    $breakGlassGroup = New-BreakGlassSecurityGroup `
        -GroupName "Break-Glass Emergency Accounts" `
        -Description "Emergency access accounts excluded from Conditional Access policies. NEVER remove members from this group without establishing replacement emergency access."
    
    # Create break-glass accounts
    Write-Host "`nCreating break-glass accounts..." -ForegroundColor Cyan
    $createdAccounts = @()
    
    for ($i = 1; $i -le $config.BreakGlassAccounts.Count; $i++) {
        $accountName = $config.BreakGlassAccounts.NamingPattern -f $i
        $upn = "$accountName@$($config.TenantDomain)"
        $displayName = "Emergency Access $i"
        $password = New-SecurePassword -Length $config.BreakGlassAccounts.PasswordLength
        
        Write-Host "`n  Creating account $i of $($config.BreakGlassAccounts.Count)..." -ForegroundColor Gray
        
        $user = New-BreakGlassUser `
            -UserPrincipalName $upn `
            -DisplayName $displayName `
            -Password $password `
            -TenantDomain $config.TenantDomain
        
        if ($user) {
            # Assign Global Administrator role
            $roleAssignment = Grant-GlobalAdminRole -UserId $user.Id -UserPrincipalName $upn
            
            # Add to break-glass security group
            if ($breakGlassGroup -and -not $WhatIfPreference) {
                try {
                    New-MgGroupMember -GroupId $breakGlassGroup.Id -DirectoryObjectId $user.Id -ErrorAction Stop | Out-Null
                    Write-Host "      [✓] Added to break-glass security group" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not add to group: $($_.Exception.Message)"
                }
            }
            
            # Split password for secure storage
            $passwordParts = Split-Password -Password $password -Parts 2
            
            $accountInfo = @{
                UserPrincipalName = $upn
                DisplayName = $displayName
                Password = $password
                PasswordPart1 = $passwordParts[0]
                PasswordPart2 = $passwordParts[1]
                StorageLocation = if ($i -le $config.BreakGlassAccounts.StorageLocations.Count) { 
                    $config.BreakGlassAccounts.StorageLocations[$i - 1] 
                } else { 
                    "Secure Location $i" 
                }
                UserId = $user.Id
            }
            
            $createdAccounts += $accountInfo
        }
    }
    
    # Output password information
    if ($createdAccounts.Count -gt 0) {
        Write-Host "`n=====================================" -ForegroundColor Yellow
        Write-Host "  CRITICAL: Break-Glass Credentials" -ForegroundColor Yellow
        Write-Host "=====================================" -ForegroundColor Yellow
        Write-Host "`n[WARNING] Store these credentials SECURELY and SEPARATELY!" -ForegroundColor Red
        
        foreach ($account in $createdAccounts) {
            Write-Host "`n--------------------------------------------------" -ForegroundColor Yellow
            Write-Host "Account: $($account.UserPrincipalName)" -ForegroundColor Cyan
            Write-Host "Display Name: $($account.DisplayName)" -ForegroundColor Gray
            Write-Host "`nPassword (FULL): $($account.Password)" -ForegroundColor Red
            Write-Host "`nPassword Part 1: $($account.PasswordPart1)" -ForegroundColor Yellow
            Write-Host "  Store in: $($account.StorageLocation)" -ForegroundColor Gray
            Write-Host "`nPassword Part 2: $($account.PasswordPart2)" -ForegroundColor Yellow
            Write-Host "  Store in: Separate secure location" -ForegroundColor Gray
            Write-Host "--------------------------------------------------" -ForegroundColor Yellow
        }
        
        # Optionally output to file
        if ($OutputPasswordFile) {
            $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
            $passwordFile = Join-Path $scriptRoot "BREAK_GLASS_CREDENTIALS_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            
            $output = @"
BREAK-GLASS ACCOUNT CREDENTIALS
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Organization: $($config.OrganizationName)

WARNING: This file contains HIGHLY SENSITIVE credentials!
- Store securely in a fireproof safe
- Split and store in multiple secure locations
- Limit access to authorized personnel only
- Delete this file after secure storage

====================================

"@
            
            foreach ($account in $createdAccounts) {
                $output += @"
Account: $($account.UserPrincipalName)
Full Password: $($account.Password)

Password Part 1: $($account.PasswordPart1)
Storage Location: $($account.StorageLocation)

Password Part 2: $($account.PasswordPart2)
Storage Location: Separate secure location

====================================

"@
            }
            
            $output | Set-Content -Path $passwordFile -ErrorAction Stop
            Write-Host "`n[File Created] $passwordFile" -ForegroundColor Red
            Write-Host "DELETE THIS FILE after transferring to secure storage!" -ForegroundColor Red
        }
    }
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles -and $createdAccounts.Count -gt 0) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        # Don't include passwords in rollback file
        $rollbackData = $createdAccounts | ForEach-Object {
            @{
                UserPrincipalName = $_.UserPrincipalName
                DisplayName = $_.DisplayName
                UserId = $_.UserId
            }
        }
        
        $rollbackFile = New-RollbackFile `
            -Component "Break-Glass-Accounts" `
            -BeforeState @() `
            -AfterState $rollbackData `
            -ChangeDescription "Created $($createdAccounts.Count) break-glass emergency access accounts"
    }
    
    # Summary and instructions
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Break-Glass Account Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Accounts created: $($createdAccounts.Count)" -ForegroundColor Gray
    Write-Host "Security group: Break-Glass Emergency Accounts" -ForegroundColor Gray
    
    Write-Host "`nCRITICAL NEXT STEPS:" -ForegroundColor Red
    Write-Host "=====================================" -ForegroundColor Red
    Write-Host "1. IMMEDIATELY transfer passwords to secure physical storage" -ForegroundColor Yellow
    Write-Host "2. Split passwords into parts and store in SEPARATE locations:" -ForegroundColor Yellow
    foreach ($account in $createdAccounts) {
        Write-Host "   - $($account.UserPrincipalName): $($account.StorageLocation)" -ForegroundColor Gray
    }
    Write-Host "3. Document who has access to each storage location" -ForegroundColor Yellow
    Write-Host "4. Exclude break-glass group from ALL Conditional Access policies" -ForegroundColor Yellow
    Write-Host "5. Set up monitoring alerts for break-glass account sign-ins" -ForegroundColor Yellow
    Write-Host "6. Test break-glass account access quarterly" -ForegroundColor Yellow
    Write-Host "7. If using FIDO2, register security keys for break-glass accounts" -ForegroundColor Yellow
    
    Write-Host "`nSecurity Best Practices:" -ForegroundColor Cyan
    Write-Host "  - Use non-obvious account names (avoid 'emergency' or 'breakglass')" -ForegroundColor Gray
    Write-Host "  - Store in fireproof safes in different geographic locations" -ForegroundColor Gray
    Write-Host "  - Limit knowledge of existence to authorized security personnel" -ForegroundColor Gray
    Write-Host "  - Monitor usage with immediate alerts" -ForegroundColor Gray
    Write-Host "  - Document emergency access procedures" -ForegroundColor Gray
    Write-Host "  - Conduct annual review and password rotation" -ForegroundColor Gray
    
    Write-Host "`nConditional Access Exclusion:" -ForegroundColor Cyan
    Write-Host "  Exclude group: Break-Glass Emergency Accounts" -ForegroundColor Yellow
    Write-Host "  Group ID: $($breakGlassGroup.Id)" -ForegroundColor Gray
    Write-Host "  Add this group to the exclusions in all CA policies" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Break-glass account creation failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

