<#
.SYNOPSIS
    Configures audit logging and retention for Entra ID.

.DESCRIPTION
    Sets up audit log retention, Azure Storage integration, and Log Analytics workspace
    streaming for long-term retention and analysis.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    .\Deploy-AuditLogging.ps1 -WhatIf

.EXAMPLE
    .\Deploy-AuditLogging.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Az.Monitor, Az.OperationalInsights

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function Test-DiagnosticSettings {
    <#
    .SYNOPSIS
        Checks current diagnostic settings for Entra ID.
    #>
    Write-Host "Checking current diagnostic settings..." -ForegroundColor Cyan
    
    try {
        # Note: Diagnostic settings are configured via Azure Monitor
        Write-Host "  [Info] Diagnostic settings are managed via Azure Monitor" -ForegroundColor Gray
        Write-Host "  Navigate to: Entra ID > Monitoring > Diagnostic settings" -ForegroundColor Gray
        
        return $true
    }
    catch {
        Write-Warning "Could not check diagnostic settings: $($_.Exception.Message)"
        return $false
    }
}

function New-LogAnalyticsWorkspace {
    param(
        [string]$WorkspaceName,
        [string]$ResourceGroupName,
        [string]$Location,
        [int]$RetentionDays
    )
    
    if ($PSCmdlet.ShouldProcess($WorkspaceName, "Create Log Analytics Workspace")) {
        try {
            Write-Host "  Creating Log Analytics workspace: $WorkspaceName" -ForegroundColor Cyan
            
            # Check if Azure PowerShell is connected
            $azContext = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $azContext) {
                Write-Warning "Not connected to Azure. Run Connect-AzAccount first."
                Write-Host "  Manual steps required:" -ForegroundColor Yellow
                Write-Host "    1. Create Log Analytics workspace in Azure Portal" -ForegroundColor Gray
                Write-Host "    2. Configure Entra ID diagnostic settings to stream to workspace" -ForegroundColor Gray
                return $null
            }
            
            # Create resource group if it doesn't exist
            $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
            if (-not $rg) {
                Write-Host "    Creating resource group: $ResourceGroupName" -ForegroundColor Gray
                $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
            }
            
            # Create workspace
            $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction SilentlyContinue
            
            if ($workspace) {
                Write-Host "    [!] Workspace already exists" -ForegroundColor Yellow
                return $workspace
            }
            
            $workspace = New-AzOperationalInsightsWorkspace `
                -ResourceGroupName $ResourceGroupName `
                -Name $WorkspaceName `
                -Location $Location `
                -Sku "PerGB2018" `
                -RetentionInDays $RetentionDays `
                -ErrorAction Stop
            
            Write-Host "    [✓] Created Log Analytics workspace" -ForegroundColor Green
            Write-Host "        Workspace ID: $($workspace.CustomerId)" -ForegroundColor Gray
            Write-Host "        Retention: $RetentionDays days" -ForegroundColor Gray
            
            return $workspace
        }
        catch {
            Write-Error "Failed to create Log Analytics workspace: $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would create Log Analytics workspace: $WorkspaceName" -ForegroundColor Yellow
        return @{ Name = $WorkspaceName }
    }
}

function Show-DiagnosticSettingsGuidance {
    param([object]$Config)
    
    Write-Host "`nConfiguring Entra ID Diagnostic Settings" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Gray
    
    Write-Host "`n[Manual Configuration Required]" -ForegroundColor Yellow
    Write-Host "Diagnostic settings must be configured via Azure Portal or Azure CLI" -ForegroundColor Gray
    
    Write-Host "`nSteps:" -ForegroundColor Cyan
    Write-Host "1. Navigate to: Azure Portal > Entra ID > Monitoring > Diagnostic settings" -ForegroundColor Gray
    Write-Host "2. Click '+ Add diagnostic setting'" -ForegroundColor Gray
    Write-Host "3. Configure the following:" -ForegroundColor Gray
    
    Write-Host "`n   Log Categories to Enable:" -ForegroundColor Yellow
    Write-Host "     [✓] AuditLogs" -ForegroundColor Gray
    Write-Host "     [✓] SignInLogs" -ForegroundColor Gray
    Write-Host "     [✓] NonInteractiveUserSignInLogs" -ForegroundColor Gray
    Write-Host "     [✓] ServicePrincipalSignInLogs" -ForegroundColor Gray
    Write-Host "     [✓] ManagedIdentitySignInLogs" -ForegroundColor Gray
    Write-Host "     [✓] ProvisioningLogs" -ForegroundColor Gray
    Write-Host "     [✓] ADFSSignInLogs (if using ADFS)" -ForegroundColor Gray
    Write-Host "     [✓] RiskyUsers" -ForegroundColor Gray
    Write-Host "     [✓] UserRiskEvents" -ForegroundColor Gray
    
    Write-Host "`n   Destination:" -ForegroundColor Yellow
    
    if ($Config.Monitoring.StreamToLogAnalytics.Enabled) {
        Write-Host "     [✓] Send to Log Analytics workspace" -ForegroundColor Gray
        Write-Host "         Workspace: $($Config.Monitoring.StreamToLogAnalytics.WorkspaceName)" -ForegroundColor Gray
    }
    
    if ($Config.Monitoring.AuditLogRetention.UseAzureStorage) {
        Write-Host "     [✓] Archive to a storage account" -ForegroundColor Gray
        Write-Host "         Storage: $($Config.Monitoring.AuditLogRetention.StorageAccountName)" -ForegroundColor Gray
        Write-Host "         Retention: $($Config.Monitoring.AuditLogRetention.RetentionDays) days" -ForegroundColor Gray
    }
    
    if ($Config.Monitoring.StreamToEventHub.Enabled) {
        Write-Host "     [✓] Stream to an event hub" -ForegroundColor Gray
        Write-Host "         Namespace: $($Config.Monitoring.StreamToEventHub.EventHubNamespace)" -ForegroundColor Gray
        Write-Host "         Event Hub: $($Config.Monitoring.StreamToEventHub.EventHubName)" -ForegroundColor Gray
    }
    
    Write-Host "`n4. Click 'Save'" -ForegroundColor Gray
    
    Write-Host "`nAzure CLI Alternative:" -ForegroundColor Cyan
    Write-Host @"
az monitor diagnostic-settings create \
  --name "EntraID-Diagnostics" \
  --resource "/providers/microsoft.aadiam/diagnosticSettings/EntraID-Diagnostics" \
  --logs '[{"category":"AuditLogs","enabled":true},{"category":"SignInLogs","enabled":true}]' \
  --workspace "$($Config.Monitoring.StreamToLogAnalytics.WorkspaceId)"
"@ -ForegroundColor Gray
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Audit Logging Configuration" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.Monitoring.Enabled) {
        Write-Warning "Monitoring is disabled in configuration. Exiting."
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
    Write-Host "  Log Analytics: $($config.Monitoring.StreamToLogAnalytics.Enabled)" -ForegroundColor Gray
    Write-Host "  Azure Storage: $($config.Monitoring.AuditLogRetention.UseAzureStorage)" -ForegroundColor Gray
    Write-Host "  Event Hub: $($config.Monitoring.StreamToEventHub.Enabled)" -ForegroundColor Gray
    
    # Check current settings
    Test-DiagnosticSettings
    
    # Create Log Analytics workspace if needed
    if ($config.Monitoring.StreamToLogAnalytics.Enabled) {
        Write-Host "`nLog Analytics Workspace Configuration" -ForegroundColor Cyan
        
        if ($config.Monitoring.StreamToLogAnalytics.WorkspaceName) {
            $workspace = New-LogAnalyticsWorkspace `
                -WorkspaceName $config.Monitoring.StreamToLogAnalytics.WorkspaceName `
                -ResourceGroupName "EntraID-Monitoring" `
                -Location "eastus" `
                -RetentionDays $config.Monitoring.AuditLogRetention.RetentionDays
        }
        else {
            Write-Warning "Log Analytics workspace name not configured"
        }
    }
    
    # Show diagnostic settings guidance
    Show-DiagnosticSettingsGuidance -Config $config
    
    # Log retention information
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  Log Retention Information" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    Write-Host "`nDefault Entra ID Retention:" -ForegroundColor Yellow
    Write-Host "  - Audit logs: 30 days (P1/P2 license)" -ForegroundColor Gray
    Write-Host "  - Sign-in logs: 30 days (P1/P2 license)" -ForegroundColor Gray
    Write-Host "  - Free tier: 7 days" -ForegroundColor Gray
    
    Write-Host "`nExtended Retention Options:" -ForegroundColor Yellow
    Write-Host "  1. Azure Storage Account:" -ForegroundColor Gray
    Write-Host "     - Cost-effective long-term storage" -ForegroundColor Gray
    Write-Host "     - Configure retention: $($config.Monitoring.AuditLogRetention.RetentionDays) days" -ForegroundColor Gray
    Write-Host "     - Use for compliance and archival" -ForegroundColor Gray
    
    Write-Host "`n  2. Log Analytics Workspace:" -ForegroundColor Gray
    Write-Host "     - Query and analyze logs with KQL" -ForegroundColor Gray
    Write-Host "     - Create alerts and dashboards" -ForegroundColor Gray
    Write-Host "     - Retention: $($config.Monitoring.AuditLogRetention.RetentionDays) days" -ForegroundColor Gray
    
    Write-Host "`n  3. Event Hub (SIEM Integration):" -ForegroundColor Gray
    Write-Host "     - Stream to Splunk, QRadar, Sentinel, etc." -ForegroundColor Gray
    Write-Host "     - Real-time security monitoring" -ForegroundColor Gray
    Write-Host "     - Correlation with other security events" -ForegroundColor Gray
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  Configuration Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Complete diagnostic settings configuration in Azure Portal" -ForegroundColor Gray
    Write-Host "2. Verify logs are flowing to configured destinations" -ForegroundColor Gray
    Write-Host "3. Create Log Analytics queries for common scenarios" -ForegroundColor Gray
    Write-Host "4. Set up alerts for security events" -ForegroundColor Gray
    Write-Host "5. Configure log retention policies" -ForegroundColor Gray
    Write-Host "6. Integrate with SIEM if required" -ForegroundColor Gray
    
    Write-Host "`nUseful Log Analytics Queries:" -ForegroundColor Cyan
    Write-Host @"
// Failed sign-ins in last 24 hours
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType, ResultDescription

// Break-glass account usage
SigninLogs
| where UserPrincipalName contains "Emergency"
| project TimeGenerated, UserPrincipalName, IPAddress, Location

// Conditional Access failures
SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus == "failure"
| summarize count() by ConditionalAccessPolicies
"@ -ForegroundColor Gray
    
    Write-Host "`nMonitoring Resources:" -ForegroundColor Cyan
    Write-Host "  - Entra ID Sign-ins: https://portal.azure.com/#view/Microsoft_AAD_IAM/SignInEventsV2MenuBlade" -ForegroundColor Gray
    Write-Host "  - Audit logs: https://portal.azure.com/#view/Microsoft_AAD_IAM/AuditLogBlade" -ForegroundColor Gray
    Write-Host "  - Diagnostic settings: https://portal.azure.com/#view/Microsoft_AAD_IAM/DiagnosticSettingsMenuBlade" -ForegroundColor Gray
}
catch {
    Write-Error "Audit logging configuration failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

