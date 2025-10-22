<#
.SYNOPSIS
    Loads and validates the Entra ID hardening configuration file.

.DESCRIPTION
    Reads the config.json file, validates required settings, and returns a configuration object.
    Falls back to config.template.json if config.json doesn't exist.

.PARAMETER ConfigPath
    Optional path to a custom configuration file.

.PARAMETER ValidateOnly
    Only validate the configuration without returning it.

.EXAMPLE
    $config = .\Get-EntraConfig.ps1

.EXAMPLE
    .\Get-EntraConfig.ps1 -ValidateOnly
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly
)

function Test-ConfigurationValid {
    param([object]$Config)
    
    $errors = @()
    
    # Validate required fields
    if (-not $Config.TenantId -or $Config.TenantId -eq 'your-tenant-id-here') {
        $errors += "TenantId is not configured"
    }
    
    if (-not $Config.TenantDomain -or $Config.TenantDomain -eq 'yourdomain.onmicrosoft.com') {
        $errors += "TenantDomain is not configured"
    }
    
    if (-not $Config.OrganizationName -or $Config.OrganizationName -eq 'Client Organization Name') {
        $errors += "OrganizationName is not configured"
    }
    
    # Validate break-glass settings
    if ($Config.BreakGlassAccounts.Enabled) {
        if ($Config.BreakGlassAccounts.Count -lt 2) {
            $errors += "At least 2 break-glass accounts are recommended"
        }
        
        if ($Config.BreakGlassAccounts.PasswordLength -lt 16) {
            $errors += "Break-glass account password length should be at least 16 characters"
        }
        
        if (-not $Config.BreakGlassAccounts.NotificationEmails -or $Config.BreakGlassAccounts.NotificationEmails.Count -eq 0) {
            $errors += "Break-glass notification emails are not configured"
        }
    }
    
    # Validate PIM settings
    if ($Config.PIM.Enabled) {
        if ($Config.PIM.Roles.GlobalAdministrator.MaxActivationDuration -gt 8) {
            Write-Warning "Global Administrator activation duration is > 8 hours. Microsoft recommends 4 hours or less."
        }
    }
    
    # Validate Conditional Access
    if ($Config.ConditionalAccess.Enabled) {
        if ($Config.ConditionalAccess.TrustedLocations.Count -eq 0) {
            Write-Warning "No trusted locations configured. Some policies may require trusted locations."
        }
    }
    
    # Validate monitoring
    if ($Config.Monitoring.Enabled) {
        if ($Config.Monitoring.StreamToLogAnalytics.Enabled -and -not $Config.Monitoring.StreamToLogAnalytics.WorkspaceId) {
            $errors += "Log Analytics is enabled but WorkspaceId is not configured"
        }
    }
    
    return $errors
}

try {
    # Determine config file path
    if (-not $ConfigPath) {
        $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $ConfigPath = Join-Path $scriptRoot "config.json"
        
        # Check if config.json exists, fall back to template
        if (-not (Test-Path $ConfigPath)) {
            $templatePath = Join-Path $scriptRoot "config.template.json"
            
            if (Test-Path $templatePath) {
                Write-Warning "config.json not found. Using config.template.json"
                Write-Warning "Please copy config.template.json to config.json and customize it for your environment."
                $ConfigPath = $templatePath
            }
            else {
                throw "Neither config.json nor config.template.json found in $scriptRoot"
            }
        }
    }
    
    Write-Verbose "Loading configuration from: $ConfigPath"
    
    # Load configuration
    $configContent = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
    $config = $configContent | ConvertFrom-Json -ErrorAction Stop
    
    Write-Host "Configuration loaded successfully" -ForegroundColor Green
    Write-Host "Organization: $($config.OrganizationName)" -ForegroundColor Gray
    Write-Host "Tenant: $($config.TenantDomain)" -ForegroundColor Gray
    
    # Validate configuration
    Write-Verbose "Validating configuration..."
    $validationErrors = Test-ConfigurationValid -Config $config
    
    if ($validationErrors.Count -gt 0) {
        Write-Warning "Configuration validation found issues:"
        foreach ($error in $validationErrors) {
            Write-Warning "  - $error"
        }
        
        if ($config.TenantId -eq 'your-tenant-id-here') {
            throw "Configuration is using template values. Please customize config.json before proceeding."
        }
    }
    
    if ($ValidateOnly) {
        if ($validationErrors.Count -eq 0) {
            Write-Host "Configuration is valid!" -ForegroundColor Green
            return $true
        }
        else {
            Write-Error "Configuration has validation errors"
            return $false
        }
    }
    
    # Add config file path to object for reference
    $config | Add-Member -MemberType NoteProperty -Name 'ConfigFilePath' -Value $ConfigPath -Force
    
    return $config
}
catch {
    Write-Error "Failed to load configuration: $($_.Exception.Message)"
    throw
}

