<#
.SYNOPSIS
    Blocks legacy authentication protocols in Entra ID.

.DESCRIPTION
    Creates Conditional Access policy to block legacy authentication protocols (IMAP, POP, SMTP, etc.)
    that bypass MFA. This is a critical security control to prevent authentication bypass attacks.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.PARAMETER ReportOnly
    Create policy in report-only mode first.

.EXAMPLE
    .\Block-LegacyAuth.ps1 -WhatIf

.EXAMPLE
    .\Block-LegacyAuth.ps1 -ReportOnly

.EXAMPLE
    .\Block-LegacyAuth.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function Test-LegacyAuthUsage {
    <#
    .SYNOPSIS
        Analyzes sign-in logs to identify legacy authentication usage.
    #>
    Write-Host "`nAnalyzing legacy authentication usage..." -ForegroundColor Cyan
    
    try {
        # Get sign-ins from the last 30 days using legacy auth
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        
        Write-Host "  Querying sign-in logs (last 30 days)..." -ForegroundColor Gray
        
        # Note: This requires appropriate permissions and may take time
        $legacySignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $thirtyDaysAgo and clientAppUsed ne 'Modern Auth Client'" -Top 1000 -ErrorAction SilentlyContinue
        
        if ($legacySignIns) {
            $uniqueUsers = $legacySignIns | Select-Object -ExpandProperty UserPrincipalName -Unique
            $clientApps = $legacySignIns | Group-Object ClientAppUsed | Select-Object Name, Count
            
            Write-Host "`n  Legacy Authentication Usage Detected:" -ForegroundColor Yellow
            Write-Host "  Total legacy auth sign-ins: $($legacySignIns.Count)" -ForegroundColor Yellow
            Write-Host "  Unique users: $($uniqueUsers.Count)" -ForegroundColor Yellow
            
            Write-Host "`n  Client applications:" -ForegroundColor Gray
            foreach ($app in $clientApps) {
                Write-Host "    - $($app.Name): $($app.Count) sign-ins" -ForegroundColor Gray
            }
            
            return @{
                HasLegacyAuth = $true
                SignInCount = $legacySignIns.Count
                UniqueUsers = $uniqueUsers.Count
                ClientApps = $clientApps
            }
        }
        else {
            Write-Host "  [✓] No legacy authentication usage detected" -ForegroundColor Green
            return @{
                HasLegacyAuth = $false
                SignInCount = 0
                UniqueUsers = 0
                ClientApps = @()
            }
        }
    }
    catch {
        Write-Warning "Could not analyze sign-in logs: $($_.Exception.Message)"
        Write-Host "  Proceeding with policy creation..." -ForegroundColor Gray
        return $null
    }
}

function New-BlockLegacyAuthPolicy {
    param(
        [string[]]$ExcludeUsers,
        [string[]]$ExcludeGroups,
        [bool]$ReportOnly
    )
    
    $state = if ($ReportOnly) { "enabledForReportingButNotEnforced" } else { "enabled" }
    $policyName = "HARDENING: Block Legacy Authentication"
    
    # Legacy authentication client apps to block
    $legacyClientApps = @(
        "exchangeActiveSync",
        "other"  # This includes IMAP, POP, SMTP, etc.
    )
    
    $policy = @{
        displayName = $policyName
        state = $state
        conditions = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $ExcludeUsers
                excludeGroups = $ExcludeGroups
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes = $legacyClientApps
        }
        grantControls = @{
            operator = "OR"
            builtInControls = @("block")
        }
    }
    
    if ($PSCmdlet.ShouldProcess($policyName, "Create Conditional Access Policy")) {
        try {
            # Check if policy already exists
            $existingPolicy = Get-MgIdentityConditionalAccessPolicy -All | 
                Where-Object { $_.DisplayName -eq $policyName }
            
            if ($existingPolicy) {
                Write-Warning "Policy '$policyName' already exists. Updating..."
                
                $updatedPolicy = Update-MgIdentityConditionalAccessPolicy `
                    -ConditionalAccessPolicyId $existingPolicy.Id `
                    -BodyParameter $policy `
                    -ErrorAction Stop
                
                Write-Host "  [✓] Updated policy: $policyName" -ForegroundColor Green
                return $updatedPolicy
            }
            else {
                $createdPolicy = New-MgIdentityConditionalAccessPolicy `
                    -BodyParameter $policy `
                    -ErrorAction Stop
                
                Write-Host "  [✓] Created policy: $policyName" -ForegroundColor Green
                return $createdPolicy
            }
        }
        catch {
            Write-Error "Failed to create/update policy: $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create policy: $policyName (State: $state)" -ForegroundColor Yellow
        return $policy
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Block Legacy Authentication" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.ConditionalAccess.BaselinePolicies.BlockLegacyAuth) {
        Write-Warning "Block legacy authentication is disabled in configuration. Exiting."
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
    
    # Analyze current legacy auth usage
    $usageAnalysis = Test-LegacyAuthUsage
    
    if ($usageAnalysis -and $usageAnalysis.HasLegacyAuth) {
        Write-Host "`n[WARNING] Legacy authentication is currently in use!" -ForegroundColor Yellow
        Write-Host "Before blocking, ensure affected users migrate to modern authentication." -ForegroundColor Yellow
        Write-Host "`nRecommendations:" -ForegroundColor Yellow
        Write-Host "  1. Contact affected users to update their email client configuration" -ForegroundColor Gray
        Write-Host "  2. Enable OAuth for email clients (Outlook, mobile mail apps)" -ForegroundColor Gray
        Write-Host "  3. Deploy this policy in report-only mode first" -ForegroundColor Gray
        Write-Host "  4. Monitor for 7-14 days before enforcement" -ForegroundColor Gray
        
        if (-not $ReportOnly -and -not $PSCmdlet.ShouldContinue(
            "Legacy authentication usage detected. Continue with enforcement?",
            "Confirm Block Legacy Auth")) {
            Write-Host "`nExiting. Use -ReportOnly flag to deploy in report-only mode." -ForegroundColor Yellow
            return
        }
    }
    
    # Capture current state
    Write-Host "`nCapturing current Conditional Access policies..." -ForegroundColor Cyan
    $existingPolicies = Get-MgIdentityConditionalAccessPolicy -All
    
    # Determine exclusions
    $excludeUsers = @()
    $excludeGroups = @()
    
    if ($config.ConditionalAccess.ExcludedUsers) {
        $excludeUsers += $config.ConditionalAccess.ExcludedUsers
    }
    
    if ($config.ConditionalAccess.ExcludedGroups) {
        $excludeGroups += $config.ConditionalAccess.ExcludedGroups
    }
    
    # Determine policy state
    $useReportOnly = $ReportOnly -or $config.DeploymentSettings.WhatIfByDefault
    
    # Create policy
    Write-Host "`nCreating Block Legacy Authentication policy..." -ForegroundColor Cyan
    
    $policy = New-BlockLegacyAuthPolicy `
        -ExcludeUsers $excludeUsers `
        -ExcludeGroups $excludeGroups `
        -ReportOnly $useReportOnly
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles -and $policy) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "Block-LegacyAuth" `
            -BeforeState $existingPolicies `
            -AfterState $policy `
            -ChangeDescription "Created policy to block legacy authentication"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Block Legacy Auth Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    
    if ($useReportOnly) {
        Write-Host "Mode: REPORT-ONLY" -ForegroundColor Yellow
        Write-Host "The policy is not enforced yet." -ForegroundColor Yellow
        Write-Host "`nMonitor sign-in logs for $($config.ConditionalAccess.ReportOnlyDuration) days:" -ForegroundColor Gray
        Write-Host "  1. Review Conditional Access > Insights and reporting" -ForegroundColor Gray
        Write-Host "  2. Identify any legitimate legacy auth usage" -ForegroundColor Gray
        Write-Host "  3. Work with affected users to migrate to modern auth" -ForegroundColor Gray
        Write-Host "  4. Re-run without -ReportOnly flag to enforce" -ForegroundColor Gray
    }
    else {
        Write-Host "Mode: ENFORCED" -ForegroundColor Green
        Write-Host "Legacy authentication is now blocked!" -ForegroundColor Green
        Write-Host "`nBlocked protocols:" -ForegroundColor Gray
        Write-Host "  - IMAP" -ForegroundColor Gray
        Write-Host "  - POP3" -ForegroundColor Gray
        Write-Host "  - SMTP AUTH" -ForegroundColor Gray
        Write-Host "  - Exchange ActiveSync (non-OAuth)" -ForegroundColor Gray
        Write-Host "  - Older Office clients" -ForegroundColor Gray
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Monitor sign-in logs for blocked attempts" -ForegroundColor Gray
    Write-Host "2. Ensure users are using modern authentication clients" -ForegroundColor Gray
    Write-Host "3. Configure email clients to use OAuth 2.0" -ForegroundColor Gray
    Write-Host "4. Review and minimize policy exclusions regularly" -ForegroundColor Gray
    
    Write-Host "`nModern Authentication Guidance:" -ForegroundColor Cyan
    Write-Host "  Outlook: Use Office 365 or Outlook 2016+" -ForegroundColor Gray
    Write-Host "  Mobile: Use Outlook Mobile app or native mail apps with OAuth" -ForegroundColor Gray
    Write-Host "  Other: Configure apps to use OAuth 2.0 / Modern Auth" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Block legacy authentication failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

