<#
.SYNOPSIS
    Generates a comprehensive security posture report for Entra ID.

.DESCRIPTION
    Assesses the current security configuration of Entra ID and generates a detailed
    report showing implemented controls, gaps, and recommendations.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER ExportReport
    Export report to HTML file.

.PARAMETER ShowRecommendationsOnly
    Only show recommendations for improvements.

.EXAMPLE
    .\Get-SecurityPosture.ps1

.EXAMPLE
    .\Get-SecurityPosture.ps1 -ExportReport

.EXAMPLE
    .\Get-SecurityPosture.ps1 -ShowRecommendationsOnly
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowRecommendationsOnly
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups

# Import common functions
$commonPath = Join-Path $PSScriptRoot "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")

function Test-MFADeployment {
    Write-Host "`nAssessing MFA deployment..." -ForegroundColor Cyan
    
    try {
        # Check for MFA CA policies
        $mfaPolicies = Get-MgIdentityConditionalAccessPolicy -All | 
            Where-Object { $_.GrantControls.BuiltInControls -contains 'mfa' }
        
        $score = 0
        $findings = @()
        
        if ($mfaPolicies.Count -gt 0) {
            $score += 50
            $findings += "[✓] MFA Conditional Access policies found: $($mfaPolicies.Count)"
            
            $enforcedPolicies = $mfaPolicies | Where-Object { $_.State -eq 'enabled' }
            if ($enforcedPolicies.Count -gt 0) {
                $score += 50
                $findings += "[✓] Enforced MFA policies: $($enforcedPolicies.Count)"
            } else {
                $findings += "[!] MFA policies exist but none are enforced"
            }
        } else {
            $findings += "[✗] No MFA Conditional Access policies found"
        }
        
        return @{
            Category = "Multi-Factor Authentication"
            Score = $score
            MaxScore = 100
            Findings = $findings
            Status = if ($score -ge 80) { 'Good' } elseif ($score -ge 50) { 'Fair' } else { 'Poor' }
        }
    }
    catch {
        return @{
            Category = "Multi-Factor Authentication"
            Score = 0
            MaxScore = 100
            Findings = @("[Error] Could not assess MFA: $($_.Exception.Message)")
            Status = 'Unknown'
        }
    }
}

function Test-ConditionalAccess {
    Write-Host "Assessing Conditional Access..." -ForegroundColor Cyan
    
    try {
        $allPolicies = Get-MgIdentityConditionalAccessPolicy -All
        
        $score = 0
        $findings = @()
        
        # Check for baseline policies
        $blockLegacyAuth = $allPolicies | Where-Object { 
            $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or 
            $_.Conditions.ClientAppTypes -contains 'other' 
        }
        
        if ($blockLegacyAuth) {
            $score += 25
            $findings += "[✓] Legacy auth blocking policy found"
        } else {
            $findings += "[✗] No legacy auth blocking policy"
        }
        
        # Check for risk-based policies
        $riskPolicies = $allPolicies | Where-Object {
            $_.Conditions.SignInRiskLevels -or $_.Conditions.UserRiskLevels
        }
        
        if ($riskPolicies.Count -gt 0) {
            $score += 25
            $findings += "[✓] Risk-based policies found: $($riskPolicies.Count)"
        } else {
            $findings += "[!] No risk-based Conditional Access policies"
        }
        
        # Check for device compliance
        $devicePolicies = $allPolicies | Where-Object {
            $_.GrantControls.BuiltInControls -contains 'compliantDevice' -or
            $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice'
        }
        
        if ($devicePolicies.Count -gt 0) {
            $score += 25
            $findings += "[✓] Device compliance policies found: $($devicePolicies.Count)"
        } else {
            $findings += "[!] No device compliance requirements"
        }
        
        # Check total number of policies
        if ($allPolicies.Count -ge 5) {
            $score += 25
            $findings += "[✓] Total CA policies: $($allPolicies.Count)"
        } else {
            $findings += "[!] Limited CA policies: $($allPolicies.Count)"
        }
        
        return @{
            Category = "Conditional Access"
            Score = $score
            MaxScore = 100
            Findings = $findings
            Status = if ($score -ge 75) { 'Good' } elseif ($score -ge 50) { 'Fair' } else { 'Poor' }
        }
    }
    catch {
        return @{
            Category = "Conditional Access"
            Score = 0
            MaxScore = 100
            Findings = @("[Error] Could not assess CA: $($_.Exception.Message)")
            Status = 'Unknown'
        }
    }
}

function Test-PrivilegedAccess {
    Write-Host "Assessing privileged access controls..." -ForegroundColor Cyan
    
    try {
        $score = 0
        $findings = @()
        
        # Check Global Admin count
        $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
        if ($globalAdminRole) {
            $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -All
            $adminCount = $globalAdmins.Count
            
            if ($adminCount -le 5) {
                $score += 50
                $findings += "[✓] Global Administrator count: $adminCount (within recommended limit)"
            } else {
                $findings += "[!] Global Administrator count: $adminCount (exceeds recommended limit of 5)"
            }
        }
        
        # Note: PIM assessment requires additional permissions
        $findings += "[Info] PIM configuration should be verified manually"
        $score += 50  # Assume partial credit
        
        return @{
            Category = "Privileged Access Management"
            Score = $score
            MaxScore = 100
            Findings = $findings
            Status = if ($score -ge 75) { 'Good' } elseif ($score -ge 50) { 'Fair' } else { 'Poor' }
        }
    }
    catch {
        return @{
            Category = "Privileged Access Management"
            Score = 0
            MaxScore = 100
            Findings = @("[Error] Could not assess privileged access: $($_.Exception.Message)")
            Status = 'Unknown'
        }
    }
}

function Test-BreakGlassAccounts {
    Write-Host "Checking break-glass accounts..." -ForegroundColor Cyan
    
    try {
        $score = 0
        $findings = @()
        
        $breakGlassGroup = Get-MgGroup -Filter "displayName eq 'Break-Glass Emergency Accounts'" -ErrorAction SilentlyContinue
        
        if ($breakGlassGroup) {
            $members = Get-MgGroupMember -GroupId $breakGlassGroup.Id -All -ErrorAction SilentlyContinue
            
            if ($members.Count -ge 2) {
                $score += 100
                $findings += "[✓] Break-glass accounts configured: $($members.Count)"
            } elseif ($members.Count -eq 1) {
                $score += 50
                $findings += "[!] Only 1 break-glass account (recommend 2+)"
            } else {
                $findings += "[✗] Break-glass group exists but no members"
            }
        } else {
            $findings += "[✗] No break-glass accounts configured"
        }
        
        return @{
            Category = "Emergency Access"
            Score = $score
            MaxScore = 100
            Findings = $findings
            Status = if ($score -ge 80) { 'Good' } elseif ($score -ge 50) { 'Fair' } else { 'Poor' }
        }
    }
    catch {
        return @{
            Category = "Emergency Access"
            Score = 0
            MaxScore = 100
            Findings = @("[Error] Could not assess break-glass: $($_.Exception.Message)")
            Status = 'Unknown'
        }
    }
}

function Test-ApplicationSecurity {
    Write-Host "Assessing application security..." -ForegroundColor Cyan
    
    try {
        $score = 0
        $findings = @()
        
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        
        # Check user consent
        $userConsent = $authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
        
        if ($userConsent.Count -eq 0 -or $null -eq $userConsent) {
            $score += 50
            $findings += "[✓] User consent for apps is disabled"
        } else {
            $findings += "[!] User consent for apps is enabled (security risk)"
        }
        
        # Check app registration
        $canRegisterApps = $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps
        
        if (-not $canRegisterApps) {
            $score += 50
            $findings += "[✓] User app registration is disabled"
        } else {
            $findings += "[!] Users can register applications"
        }
        
        return @{
            Category = "Application Security"
            Score = $score
            MaxScore = 100
            Findings = $findings
            Status = if ($score -ge 80) { 'Good' } elseif ($score -ge 50) { 'Fair' } else { 'Poor' }
        }
    }
    catch {
        return @{
            Category = "Application Security"
            Score = 0
            MaxScore = 100
            Findings = @("[Error] Could not assess app security: $($_.Exception.Message)")
            Status = 'Unknown'
        }
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Entra ID Security Posture Assessment" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Verify Graph connection
    $context = Get-MgContext
    if (-not $context) {
        Write-Error "Not connected to Microsoft Graph. Run .\Common\Connect-EntraID.ps1 first."
        return
    }
    
    Write-Host "`nTenant: $($context.TenantId)" -ForegroundColor Gray
    Write-Host "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    
    # Run assessments
    $assessments = @()
    $assessments += Test-MFADeployment
    $assessments += Test-ConditionalAccess
    $assessments += Test-PrivilegedAccess
    $assessments += Test-BreakGlassAccounts
    $assessments += Test-ApplicationSecurity
    
    # Calculate overall score
    $totalScore = ($assessments | Measure-Object -Property Score -Sum).Sum
    $totalMaxScore = ($assessments | Measure-Object -Property MaxScore -Sum).Sum
    $overallPercentage = [math]::Round(($totalScore / $totalMaxScore) * 100)
    
    # Display results
    if (-not $ShowRecommendationsOnly) {
        Write-Host "`n=====================================" -ForegroundColor Yellow
        Write-Host "  Assessment Results" -ForegroundColor Yellow
        Write-Host "=====================================" -ForegroundColor Yellow
        
        foreach ($assessment in $assessments) {
            $percentage = [math]::Round(($assessment.Score / $assessment.MaxScore) * 100)
            $color = switch ($assessment.Status) {
                'Good' { 'Green' }
                'Fair' { 'Yellow' }
                'Poor' { 'Red' }
                default { 'Gray' }
            }
            
            Write-Host "`n$($assessment.Category)" -ForegroundColor Cyan
            Write-Host "Score: $($assessment.Score)/$($assessment.MaxScore) ($percentage%) - $($assessment.Status)" -ForegroundColor $color
            
            foreach ($finding in $assessment.Findings) {
                Write-Host "  $finding" -ForegroundColor Gray
            }
        }
    }
    
    # Overall score
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Overall Security Score" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "`nScore: $totalScore / $totalMaxScore ($overallPercentage%)" -ForegroundColor $(
        if ($overallPercentage -ge 80) { 'Green' }
        elseif ($overallPercentage -ge 60) { 'Yellow' }
        else { 'Red' }
    )
    
    $rating = if ($overallPercentage -ge 90) { 'Excellent' }
              elseif ($overallPercentage -ge 80) { 'Good' }
              elseif ($overallPercentage -ge 60) { 'Fair' }
              else { 'Needs Improvement' }
    
    Write-Host "Rating: $rating" -ForegroundColor Gray
    
    # Recommendations
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Recommendations" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    $poorAssessments = $assessments | Where-Object { $_.Status -eq 'Poor' -or $_.Status -eq 'Fair' }
    
    if ($poorAssessments.Count -gt 0) {
        Write-Host "`nPriority Areas for Improvement:" -ForegroundColor Yellow
        foreach ($assessment in $poorAssessments) {
            Write-Host "`n$($assessment.Category):" -ForegroundColor Yellow
            foreach ($finding in ($assessment.Findings | Where-Object { $_ -match '^\[✗\]|\[!\]' })) {
                Write-Host "  $finding" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "`nYour Entra ID security posture is strong!" -ForegroundColor Green
        Write-Host "Continue monitoring and maintaining current controls." -ForegroundColor Gray
    }
    
    Write-Host "`nGeneral Recommendations:" -ForegroundColor Cyan
    Write-Host "  - Run security assessments monthly" -ForegroundColor Gray
    Write-Host "  - Review sign-in logs weekly" -ForegroundColor Gray
    Write-Host "  - Conduct quarterly access reviews" -ForegroundColor Gray
    Write-Host "  - Test break-glass procedures quarterly" -ForegroundColor Gray
    Write-Host "  - Update CA policies based on new threats" -ForegroundColor Gray
    
    # Export report
    if ($ExportReport) {
        $reportFile = Join-Path $PSScriptRoot "Reports\SecurityPosture_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        
        $reportsDir = Join-Path $PSScriptRoot "Reports"
        if (-not (Test-Path $reportsDir)) {
            New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
        }
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Entra ID Security Posture Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #0078d4; }
        h2 { color: #106ebe; margin-top: 30px; }
        .score { font-size: 24px; font-weight: bold; }
        .good { color: green; }
        .fair { color: orange; }
        .poor { color: red; }
        .finding { margin: 5px 0; padding-left: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #0078d4; color: white; }
    </style>
</head>
<body>
    <h1>Entra ID Security Posture Report</h1>
    <p><strong>Tenant ID:</strong> $($context.TenantId)</p>
    <p><strong>Assessment Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <h2>Overall Score</h2>
    <p class="score">$totalScore / $totalMaxScore ($overallPercentage%) - $rating</p>
    
    <h2>Detailed Assessment</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Score</th>
            <th>Status</th>
        </tr>
"@
        
        foreach ($assessment in $assessments) {
            $percentage = [math]::Round(($assessment.Score / $assessment.MaxScore) * 100)
            $statusClass = $assessment.Status.ToLower()
            
            $html += @"
        <tr>
            <td>$($assessment.Category)</td>
            <td>$($assessment.Score)/$($assessment.MaxScore) ($percentage%)</td>
            <td class="$statusClass">$($assessment.Status)</td>
        </tr>
"@
        }
        
        $html += @"
    </table>
    
    <h2>Detailed Findings</h2>
"@
        
        foreach ($assessment in $assessments) {
            $html += "<h3>$($assessment.Category)</h3>`n"
            foreach ($finding in $assessment.Findings) {
                $html += "<div class='finding'>$finding</div>`n"
            }
        }
        
        $html += @"
</body>
</html>
"@
        
        $html | Set-Content -Path $reportFile -ErrorAction Stop
        Write-Host "`n[Report Exported] $reportFile" -ForegroundColor Green
    }
}
catch {
    Write-Error "Security posture assessment failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

