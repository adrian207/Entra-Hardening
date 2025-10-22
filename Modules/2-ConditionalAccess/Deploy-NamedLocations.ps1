<#
.SYNOPSIS
    Configures named locations (trusted IPs) for Conditional Access policies.

.DESCRIPTION
    Creates named locations in Entra ID based on configuration file, including trusted
    corporate network locations and countries/regions.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    .\Deploy-NamedLocations.ps1 -WhatIf

.EXAMPLE
    .\Deploy-NamedLocations.ps1
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

function New-NamedLocation {
    param(
        [string]$Name,
        [string[]]$IpRanges,
        [string[]]$CountriesAndRegions,
        [bool]$IsTrusted
    )
    
    if ($PSCmdlet.ShouldProcess($Name, "Create Named Location")) {
        try {
            # Check if location already exists
            $existing = Get-MgIdentityConditionalAccessNamedLocation -All | 
                Where-Object { $_.DisplayName -eq $Name }
            
            if ($existing) {
                Write-Host "  [!] Location '$Name' already exists - skipping" -ForegroundColor Yellow
                return $existing
            }
            
            if ($IpRanges -and $IpRanges.Count -gt 0) {
                # Create IP-based named location
                $ipRangeObjects = $IpRanges | ForEach-Object {
                    @{ cidrAddress = $_ }
                }
                
                $location = @{
                    "@odata.type" = "#microsoft.graph.ipNamedLocation"
                    displayName = $Name
                    isTrusted = $IsTrusted
                    ipRanges = $ipRangeObjects
                }
                
                $created = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $location -ErrorAction Stop
                Write-Host "  [✓] Created IP location: $Name ($($IpRanges.Count) ranges)" -ForegroundColor Green
                return $created
            }
            elseif ($CountriesAndRegions -and $CountriesAndRegions.Count -gt 0) {
                # Create country-based named location
                $location = @{
                    "@odata.type" = "#microsoft.graph.countryNamedLocation"
                    displayName = $Name
                    countriesAndRegions = $CountriesAndRegions
                    includeUnknownCountriesAndRegions = $false
                }
                
                $created = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $location -ErrorAction Stop
                Write-Host "  [✓] Created country location: $Name ($($CountriesAndRegions.Count) countries)" -ForegroundColor Green
                return $created
            }
            else {
                Write-Warning "Location '$Name' has no IP ranges or countries defined - skipping"
                return $null
            }
        }
        catch {
            Write-Error "Failed to create location '$Name': $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create named location: $Name" -ForegroundColor Yellow
        return @{ DisplayName = $Name }
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Named Locations Deployment" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.ConditionalAccess.Enabled) {
        Write-Warning "Conditional Access is disabled in configuration. Exiting."
        return
    }
    
    if (-not $config.ConditionalAccess.TrustedLocations -or $config.ConditionalAccess.TrustedLocations.Count -eq 0) {
        Write-Warning "No trusted locations configured in config file."
        Write-Host "`nTo configure trusted locations, edit config.json:" -ForegroundColor Yellow
        Write-Host @"
  "TrustedLocations": [
    {
      "Name": "Corporate Office",
      "IpRanges": ["203.0.113.0/24"],
      "CountriesAndRegions": [],
      "TrustedLocation": true
    }
  ]
"@ -ForegroundColor Gray
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
    Write-Host "  Locations to create: $($config.ConditionalAccess.TrustedLocations.Count)" -ForegroundColor Gray
    
    # Capture current state
    Write-Host "`nCapturing existing named locations..." -ForegroundColor Cyan
    $existingLocations = Get-MgIdentityConditionalAccessNamedLocation -All
    Write-Host "  Found $($existingLocations.Count) existing locations" -ForegroundColor Gray
    
    # Create named locations
    Write-Host "`nCreating named locations..." -ForegroundColor Cyan
    $createdLocations = @()
    
    foreach ($location in $config.ConditionalAccess.TrustedLocations) {
        $created = New-NamedLocation `
            -Name $location.Name `
            -IpRanges $location.IpRanges `
            -CountriesAndRegions $location.CountriesAndRegions `
            -IsTrusted $location.TrustedLocation
        
        if ($created) {
            $createdLocations += $created
        }
    }
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles -and $createdLocations.Count -gt 0) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "Named-Locations" `
            -BeforeState $existingLocations `
            -AfterState $createdLocations `
            -ChangeDescription "Created named locations for Conditional Access"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Named Locations Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Locations created: $($createdLocations.Count)" -ForegroundColor Gray
    
    foreach ($location in $createdLocations) {
        Write-Host "  [✓] $($location.DisplayName)" -ForegroundColor Green
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Verify IP ranges are correct for your network" -ForegroundColor Gray
    Write-Host "2. Use named locations in Conditional Access policies" -ForegroundColor Gray
    Write-Host "3. Consider policies like:" -ForegroundColor Gray
    Write-Host "   - Block access from outside trusted locations for admins" -ForegroundColor Gray
    Write-Host "   - Require MFA when not on trusted network" -ForegroundColor Gray
    Write-Host "   - Block specific countries/regions" -ForegroundColor Gray
    
    Write-Host "`nBest Practices:" -ForegroundColor Yellow
    Write-Host "  - Keep IP ranges up to date as network changes" -ForegroundColor Gray
    Write-Host "  - Don't rely solely on IP for security (can be spoofed)" -ForegroundColor Gray
    Write-Host "  - Combine with device compliance and MFA" -ForegroundColor Gray
    Write-Host "  - Use country blocking cautiously (may affect legitimate users)" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Named locations deployment failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

