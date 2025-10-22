<#
.SYNOPSIS
    Establishes connection to Microsoft Entra ID (Azure AD) with required permissions.

.DESCRIPTION
    Connects to Microsoft Graph with the necessary scopes for Entra ID hardening operations.
    Validates connection and permissions before proceeding.

.PARAMETER Scopes
    Optional array of additional Microsoft Graph scopes to request.

.PARAMETER UseDeviceCode
    Use device code flow for authentication (useful for remote sessions).

.EXAMPLE
    .\Connect-EntraID.ps1

.EXAMPLE
    .\Connect-EntraID.ps1 -UseDeviceCode
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$Scopes,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode
)

# Required scopes for Entra ID hardening
$RequiredScopes = @(
    'Directory.Read.All',
    'Directory.ReadWrite.All',
    'Policy.Read.All',
    'Policy.ReadWrite.ConditionalAccess',
    'Policy.ReadWrite.AuthenticationMethod',
    'RoleManagement.ReadWrite.Directory',
    'PrivilegedAccess.ReadWrite.AzureAD',
    'AuditLog.Read.All',
    'Application.Read.All',
    'Application.ReadWrite.All',
    'User.ReadWrite.All',
    'Group.ReadWrite.All',
    'IdentityRiskyUser.ReadWrite.All',
    'IdentityRiskEvent.Read.All'
)

# Combine required scopes with any additional scopes
if ($Scopes) {
    $AllScopes = $RequiredScopes + $Scopes | Select-Object -Unique
} else {
    $AllScopes = $RequiredScopes
}

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "Required scopes: $($AllScopes.Count)" -ForegroundColor Gray

try {
    # Disconnect any existing session
    $existingConnection = Get-MgContext -ErrorAction SilentlyContinue
    if ($existingConnection) {
        Write-Host "Disconnecting existing session..." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
    }
    
    # Connect to Microsoft Graph
    $connectParams = @{
        Scopes = $AllScopes
        ErrorAction = 'Stop'
    }
    
    if ($UseDeviceCode) {
        $connectParams.Add('UseDeviceCode', $true)
    }
    
    Connect-MgGraph @connectParams | Out-Null
    
    # Verify connection
    $context = Get-MgContext
    
    if (-not $context) {
        throw "Failed to establish connection to Microsoft Graph"
    }
    
    Write-Host "`nConnection successful!" -ForegroundColor Green
    Write-Host "Tenant ID: $($context.TenantId)" -ForegroundColor Gray
    Write-Host "Account: $($context.Account)" -ForegroundColor Gray
    Write-Host "Scopes: $($context.Scopes.Count) permissions granted" -ForegroundColor Gray
    
    # Validate critical permissions
    $criticalScopes = @('Directory.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'RoleManagement.ReadWrite.Directory')
    $missingScopes = $criticalScopes | Where-Object { $_ -notin $context.Scopes }
    
    if ($missingScopes) {
        Write-Warning "Missing critical permissions: $($missingScopes -join ', ')"
        Write-Warning "Some operations may fail. Consider running with elevated permissions."
    }
    
    # Check if user has required admin roles
    Write-Host "`nValidating administrator roles..." -ForegroundColor Cyan
    try {
        $me = Get-MgUser -UserId $context.Account -Property Id, UserPrincipalName -ErrorAction Stop
        $myRoles = Get-MgUserMemberOf -UserId $me.Id -All -ErrorAction SilentlyContinue | 
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }
        
        $roleNames = $myRoles | ForEach-Object { $_.AdditionalProperties.displayName }
        
        $requiredRoles = @('Global Administrator', 'Security Administrator', 'Conditional Access Administrator')
        $hasRequiredRole = $false
        
        foreach ($role in $requiredRoles) {
            if ($roleNames -contains $role) {
                Write-Host "  [✓] $role role detected" -ForegroundColor Green
                $hasRequiredRole = $true
                break
            }
        }
        
        if (-not $hasRequiredRole) {
            Write-Warning "Current account does not have required administrator roles."
            Write-Warning "You need one of: $($requiredRoles -join ', ')"
            Write-Warning "Some operations may be restricted."
        }
    }
    catch {
        Write-Warning "Could not validate administrator roles: $($_.Exception.Message)"
    }
    
    Write-Host "`nReady to execute Entra ID hardening scripts." -ForegroundColor Green
    return $true
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have Microsoft.Graph PowerShell module installed" -ForegroundColor Gray
    Write-Host "2. Verify you have appropriate permissions in the tenant" -ForegroundColor Gray
    Write-Host "3. Try using -UseDeviceCode parameter for alternative authentication" -ForegroundColor Gray
    return $false
}

