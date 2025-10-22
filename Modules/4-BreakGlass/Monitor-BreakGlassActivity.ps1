<#
.SYNOPSIS
    Monitors and alerts on break-glass account usage.

.DESCRIPTION
    Checks sign-in logs for break-glass account activity and sends alerts.
    Should be run on a schedule to detect unauthorized use.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER DaysToCheck
    Number of days of sign-in history to check (default: 1).

.PARAMETER SendAlert
    Send email alert if break-glass activity detected.

.EXAMPLE
    .\Monitor-BreakGlassActivity.ps1

.EXAMPLE
    .\Monitor-BreakGlassActivity.ps1 -DaysToCheck 7 -SendAlert
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysToCheck = 1,
    
    [Parameter(Mandatory = $false)]
    [switch]$SendAlert
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Reports

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")

function Get-BreakGlassAccounts {
    <#
    .SYNOPSIS
        Retrieves break-glass accounts from the designated security group.
    #>
    try {
        $group = Get-MgGroup -Filter "displayName eq 'Break-Glass Emergency Accounts'" -ErrorAction SilentlyContinue
        
        if (-not $group) {
            Write-Warning "Break-Glass Emergency Accounts group not found"
            return @()
        }
        
        $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop
        
        $breakGlassAccounts = @()
        foreach ($member in $members) {
            if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                $user = Get-MgUser -UserId $member.Id -Property Id,UserPrincipalName,DisplayName -ErrorAction SilentlyContinue
                if ($user) {
                    $breakGlassAccounts += $user
                }
            }
        }
        
        return $breakGlassAccounts
    }
    catch {
        Write-Error "Failed to retrieve break-glass accounts: $($_.Exception.Message)"
        return @()
    }
}

function Get-BreakGlassSignIns {
    param(
        [string[]]$UserPrincipalNames,
        [int]$Days
    )
    
    try {
        $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        
        $allSignIns = @()
        
        foreach ($upn in $UserPrincipalNames) {
            Write-Verbose "Checking sign-ins for: $upn"
            
            $signIns = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$upn' and createdDateTime ge $startDate" -All -ErrorAction SilentlyContinue
            
            if ($signIns) {
                $allSignIns += $signIns
            }
        }
        
        return $allSignIns
    }
    catch {
        Write-Error "Failed to retrieve sign-in logs: $($_.Exception.Message)"
        return @()
    }
}

function Send-BreakGlassAlert {
    param(
        [object[]]$SignIns,
        [string[]]$Recipients
    )
    
    Write-Host "`n[ALERT] Break-Glass Account Activity Detected!" -ForegroundColor Red
    Write-Host "=====================================" -ForegroundColor Red
    
    foreach ($signIn in $SignIns) {
        Write-Host "`nUser: $($signIn.UserPrincipalName)" -ForegroundColor Yellow
        Write-Host "Time: $($signIn.CreatedDateTime)" -ForegroundColor Gray
        Write-Host "Status: $($signIn.Status.ErrorCode)" -ForegroundColor Gray
        Write-Host "IP Address: $($signIn.IpAddress)" -ForegroundColor Gray
        Write-Host "Location: $($signIn.Location.City), $($signIn.Location.State), $($signIn.Location.CountryOrRegion)" -ForegroundColor Gray
        Write-Host "Application: $($signIn.AppDisplayName)" -ForegroundColor Gray
        Write-Host "Device: $($signIn.DeviceDetail.DisplayName)" -ForegroundColor Gray
    }
    
    Write-Host "`nAction Required:" -ForegroundColor Red
    Write-Host "1. Verify this was authorized emergency access" -ForegroundColor Yellow
    Write-Host "2. Contact the user if this was unauthorized" -ForegroundColor Yellow
    Write-Host "3. Review the reason for break-glass account usage" -ForegroundColor Yellow
    Write-Host "4. Document the incident" -ForegroundColor Yellow
    Write-Host "5. Rotate credentials if compromise suspected" -ForegroundColor Yellow
    
    # Note: Email sending would require additional configuration
    if ($SendAlert -and $Recipients) {
        Write-Host "`n[Note] Email alerting requires mail server configuration" -ForegroundColor Yellow
        Write-Host "Recipients: $($Recipients -join ', ')" -ForegroundColor Gray
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Break-Glass Account Monitoring" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    # Verify Graph connection
    $context = Get-MgContext
    if (-not $context) {
        Write-Error "Not connected to Microsoft Graph. Run Connect-EntraID.ps1 first."
        return
    }
    
    Write-Host "`nConfiguration:" -ForegroundColor Cyan
    Write-Host "  Organization: $($config.OrganizationName)" -ForegroundColor Gray
    Write-Host "  Checking last $DaysToCheck day(s)" -ForegroundColor Gray
    
    # Get break-glass accounts
    Write-Host "`nRetrieving break-glass accounts..." -ForegroundColor Cyan
    $breakGlassAccounts = Get-BreakGlassAccounts
    
    if ($breakGlassAccounts.Count -eq 0) {
        Write-Warning "No break-glass accounts found. Run New-BreakGlassAccount.ps1 first."
        return
    }
    
    Write-Host "  Found $($breakGlassAccounts.Count) break-glass account(s)" -ForegroundColor Gray
    foreach ($account in $breakGlassAccounts) {
        Write-Host "    - $($account.UserPrincipalName)" -ForegroundColor Gray
    }
    
    # Check sign-in activity
    Write-Host "`nChecking sign-in activity..." -ForegroundColor Cyan
    $upns = $breakGlassAccounts | Select-Object -ExpandProperty UserPrincipalName
    $signIns = Get-BreakGlassSignIns -UserPrincipalNames $upns -Days $DaysToCheck
    
    if ($signIns.Count -gt 0) {
        Write-Host "  [!] ACTIVITY DETECTED: $($signIns.Count) sign-in(s)" -ForegroundColor Red
        
        $recipients = $config.BreakGlassAccounts.NotificationEmails
        Send-BreakGlassAlert -SignIns $signIns -Recipients $recipients
    }
    else {
        Write-Host "  [✓] No break-glass account activity in the last $DaysToCheck day(s)" -ForegroundColor Green
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Monitoring Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Accounts monitored: $($breakGlassAccounts.Count)" -ForegroundColor Gray
    Write-Host "Sign-ins detected: $($signIns.Count)" -ForegroundColor Gray
    Write-Host "Time range: Last $DaysToCheck day(s)" -ForegroundColor Gray
    Write-Host "Check completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    
    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    Write-Host "  - Schedule this script to run daily via task scheduler" -ForegroundColor Gray
    Write-Host "  - Configure email alerts to security team" -ForegroundColor Gray
    Write-Host "  - Integrate with SIEM for centralized monitoring" -ForegroundColor Gray
    Write-Host "  - Document all break-glass account usage" -ForegroundColor Gray
    Write-Host "  - Review access quarterly even if no activity" -ForegroundColor Gray
}
catch {
    Write-Error "Break-glass monitoring failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

