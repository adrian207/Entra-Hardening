<#
.SYNOPSIS
    Audits enterprise applications and service principals in Entra ID.

.DESCRIPTION
    Scans for potentially suspicious or high-risk applications, identifies apps with
    excessive permissions, and generates a report of all enterprise applications.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER ExportReport
    Export audit results to CSV file.

.PARAMETER HighRiskOnly
    Only show high-risk applications.

.EXAMPLE
    .\Audit-EnterpriseApps.ps1

.EXAMPLE
    .\Audit-EnterpriseApps.ps1 -ExportReport

.EXAMPLE
    .\Audit-EnterpriseApps.ps1 -HighRiskOnly
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$HighRiskOnly
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")

function Get-ApplicationRiskScore {
    param([object]$App, [object]$Permissions)
    
    $riskScore = 0
    $riskFactors = @()
    
    # High-risk permissions
    $highRiskPermissions = @(
        'Mail.ReadWrite.All',
        'Mail.Send.All',
        'Files.ReadWrite.All',
        'Directory.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory',
        'User.ReadWrite.All',
        'Group.ReadWrite.All'
    )
    
    foreach ($permission in $Permissions) {
        if ($permission.Value -in $highRiskPermissions) {
            $riskScore += 20
            $riskFactors += "High-risk permission: $($permission.Value)"
        }
    }
    
    # Unverified publisher
    if (-not $App.PublisherDomain -or $App.PublisherDomain -eq 'Unknown') {
        $riskScore += 15
        $riskFactors += "Unverified publisher"
    }
    
    # Many permissions
    if ($Permissions.Count -gt 10) {
        $riskScore += 10
        $riskFactors += "Excessive permissions ($($Permissions.Count) total)"
    }
    
    # Delegated permissions (can act as user)
    $delegatedPerms = $Permissions | Where-Object { $_.Type -eq 'Delegated' }
    if ($delegatedPerms.Count -gt 5) {
        $riskScore += 10
        $riskFactors += "Many delegated permissions"
    }
    
    # Recently added
    $createdDate = $App.CreatedDateTime
    if ($createdDate -and $createdDate -gt (Get-Date).AddDays(-30)) {
        $riskScore += 5
        $riskFactors += "Recently added (< 30 days)"
    }
    
    return @{
        Score = $riskScore
        Factors = $riskFactors
        Level = if ($riskScore -ge 40) { 'High' } 
                elseif ($riskScore -ge 20) { 'Medium' } 
                else { 'Low' }
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Enterprise Application Audit" -ForegroundColor Cyan
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
    
    # Get all service principals (enterprise applications)
    Write-Host "`nRetrieving enterprise applications..." -ForegroundColor Cyan
    $servicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
    Write-Host "  Found $($servicePrincipals.Count) service principals" -ForegroundColor Gray
    
    # Filter to only third-party apps (not Microsoft)
    $thirdPartyApps = $servicePrincipals | Where-Object { 
        $_.AppOwnerOrganizationId -ne 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' -and  # Not Microsoft
        $_.Tags -notcontains 'WindowsAzureActiveDirectoryIntegratedApp'
    }
    
    Write-Host "  Third-party applications: $($thirdPartyApps.Count)" -ForegroundColor Gray
    
    # Analyze applications
    Write-Host "`nAnalyzing applications for security risks..." -ForegroundColor Cyan
    $auditResults = @()
    
    foreach ($app in $thirdPartyApps) {
        Write-Verbose "Analyzing: $($app.DisplayName)"
        
        # Get OAuth2 permissions
        $oauth2Permissions = $app.Oauth2PermissionGrants
        
        # Get app roles (application permissions)
        $appRoles = $app.AppRoles
        
        # Combine all permissions
        $allPermissions = @()
        foreach ($perm in $oauth2Permissions) {
            $allPermissions += @{
                Type = 'Delegated'
                Value = $perm.Scope
            }
        }
        
        foreach ($role in $appRoles) {
            $allPermissions += @{
                Type = 'Application'
                Value = $role.Value
            }
        }
        
        # Calculate risk
        $risk = Get-ApplicationRiskScore -App $app -Permissions $allPermissions
        
        $result = [PSCustomObject]@{
            DisplayName = $app.DisplayName
            ApplicationId = $app.AppId
            PublisherDomain = if ($app.PublisherDomain) { $app.PublisherDomain } else { 'Unknown' }
            CreatedDateTime = $app.CreatedDateTime
            PermissionCount = $allPermissions.Count
            RiskLevel = $risk.Level
            RiskScore = $risk.Score
            RiskFactors = $risk.Factors -join '; '
            ServicePrincipalId = $app.Id
        }
        
        $auditResults += $result
    }
    
    # Sort by risk score
    $auditResults = $auditResults | Sort-Object -Property RiskScore -Descending
    
    # Filter if only high-risk requested
    if ($HighRiskOnly) {
        $auditResults = $auditResults | Where-Object { $_.RiskLevel -eq 'High' }
    }
    
    # Display results
    Write-Host "`n=====================================" -ForegroundColor Yellow
    Write-Host "  Audit Results" -ForegroundColor Yellow
    Write-Host "=====================================" -ForegroundColor Yellow
    
    $highRisk = ($auditResults | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumRisk = ($auditResults | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $lowRisk = ($auditResults | Where-Object { $_.RiskLevel -eq 'Low' }).Count
    
    Write-Host "`nRisk Summary:" -ForegroundColor Cyan
    Write-Host "  High Risk: $highRisk" -ForegroundColor Red
    Write-Host "  Medium Risk: $mediumRisk" -ForegroundColor Yellow
    Write-Host "  Low Risk: $lowRisk" -ForegroundColor Green
    
    if ($highRisk -gt 0) {
        Write-Host "`nHigh-Risk Applications:" -ForegroundColor Red
        Write-Host "=====================================" -ForegroundColor Red
        
        foreach ($app in ($auditResults | Where-Object { $_.RiskLevel -eq 'High' } | Select-Object -First 10)) {
            Write-Host "`nApplication: $($app.DisplayName)" -ForegroundColor Yellow
            Write-Host "  Publisher: $($app.PublisherDomain)" -ForegroundColor Gray
            Write-Host "  Application ID: $($app.ApplicationId)" -ForegroundColor Gray
            Write-Host "  Risk Score: $($app.RiskScore)" -ForegroundColor Red
            Write-Host "  Permissions: $($app.PermissionCount)" -ForegroundColor Gray
            Write-Host "  Risk Factors:" -ForegroundColor Yellow
            foreach ($factor in ($app.RiskFactors -split '; ')) {
                Write-Host "    - $factor" -ForegroundColor Gray
            }
            Write-Host "  Created: $($app.CreatedDateTime)" -ForegroundColor Gray
        }
    }
    
    # Export report
    if ($ExportReport) {
        $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $reportFile = Join-Path $scriptRoot "Reports\EnterpriseApps_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        # Create Reports directory if it doesn't exist
        $reportsDir = Join-Path $scriptRoot "Reports"
        if (-not (Test-Path $reportsDir)) {
            New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
        }
        
        $auditResults | Export-Csv -Path $reportFile -NoTypeInformation -ErrorAction Stop
        Write-Host "`n[Report Exported] $reportFile" -ForegroundColor Green
    }
    
    # Recommendations
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Recommendations" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    Write-Host "`nActions to Take:" -ForegroundColor Yellow
    Write-Host "1. Review all high-risk applications" -ForegroundColor Gray
    Write-Host "2. Remove unused or unnecessary applications" -ForegroundColor Gray
    Write-Host "3. Verify publisher domains for unverified apps" -ForegroundColor Gray
    Write-Host "4. Review and minimize application permissions" -ForegroundColor Gray
    Write-Host "5. Enable Conditional Access for sensitive apps" -ForegroundColor Gray
    
    Write-Host "`nTo Remove an Application:" -ForegroundColor Cyan
    Write-Host "  Entra ID > Enterprise applications > [Select App] > Delete" -ForegroundColor Gray
    Write-Host "  Or use: Remove-MgServicePrincipal -ServicePrincipalId <ID>" -ForegroundColor Gray
    
    Write-Host "`nTo Review Permissions:" -ForegroundColor Cyan
    Write-Host "  Entra ID > Enterprise applications > [Select App] > Permissions" -ForegroundColor Gray
    
    Write-Host "`nSchedule Regular Audits:" -ForegroundColor Yellow
    Write-Host "  Run this script monthly to detect new suspicious applications" -ForegroundColor Gray
    Write-Host "  Schedule: Task Scheduler or Azure Automation" -ForegroundColor Gray
}
catch {
    Write-Error "Enterprise application audit failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

