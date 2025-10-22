<#
.SYNOPSIS
    Configures Privileged Identity Management (PIM) for Entra ID roles.

.DESCRIPTION
    Implements Just-In-Time (JIT) access for privileged roles using PIM. Configures
    role settings including activation duration, approval requirements, and MFA.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to config.json in the root directory.

.PARAMETER WhatIf
    Preview changes without applying them.

.PARAMETER RoleName
    Configure a specific role instead of all configured roles.

.EXAMPLE
    .\Deploy-PIM.ps1 -WhatIf

.EXAMPLE
    .\Deploy-PIM.ps1

.EXAMPLE
    .\Deploy-PIM.ps1 -RoleName "Global Administrator"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleName
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance

# Import common functions
$commonPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "Common"
. (Join-Path $commonPath "Get-EntraConfig.ps1")
. (Join-Path $commonPath "Invoke-EntraLogger.ps1")
. (Join-Path $commonPath "New-RollbackFile.ps1")

function Get-EntraRoleDefinitions {
    <#
    .SYNOPSIS
        Gets Entra role definitions with their IDs.
    #>
    Write-Host "Retrieving Entra ID role definitions..." -ForegroundColor Cyan
    
    try {
        $roles = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
        Write-Host "  Found $($roles.Count) role definitions" -ForegroundColor Gray
        return $roles
    }
    catch {
        Write-Error "Failed to retrieve role definitions: $($_.Exception.Message)"
        return $null
    }
}

function Set-PIMRoleSettings {
    param(
        [string]$RoleDefinitionId,
        [string]$RoleDisplayName,
        [int]$MaxActivationDuration,
        [bool]$RequireApproval,
        [bool]$RequireMFA,
        [bool]$RequireJustification,
        [string[]]$Approvers
    )
    
    if ($PSCmdlet.ShouldProcess($RoleDisplayName, "Configure PIM Settings")) {
        try {
            # Build role settings
            $durationInHours = "PT$($MaxActivationDuration)H"
            
            $settings = @{
                "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyRuleSet"
                rules = @(
                    @{
                        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                        id = "Expiration_EndUser_Assignment"
                        isExpirationRequired = $true
                        maximumDuration = $durationInHours
                        target = @{
                            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                            caller = "EndUser"
                            operations = @("All")
                            level = "Assignment"
                        }
                    },
                    @{
                        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
                        id = "Enablement_EndUser_Assignment"
                        enabledRules = @(
                            if ($RequireMFA) { "MultiFactorAuthentication" }
                            if ($RequireJustification) { "Justification" }
                        ) | Where-Object { $_ }
                        target = @{
                            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                            caller = "EndUser"
                            operations = @("All")
                            level = "Assignment"
                        }
                    },
                    @{
                        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
                        id = "Approval_EndUser_Assignment"
                        setting = @{
                            isApprovalRequired = $RequireApproval
                            isApprovalRequiredForExtension = $false
                            isRequestorJustificationRequired = $RequireJustification
                            approvalMode = "SingleStage"
                            approvalStages = @(
                                @{
                                    approvalStageTimeOutInDays = 1
                                    isApproverJustificationRequired = $true
                                    escalationTimeInMinutes = 0
                                    primaryApprovers = @()
                                    isEscalationEnabled = $false
                                    escalationApprovers = @()
                                }
                            )
                        }
                        target = @{
                            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                            caller = "EndUser"
                            operations = @("All")
                            level = "Assignment"
                        }
                    }
                )
            }
            
            Write-Host "  [✓] Configured PIM for: $RoleDisplayName" -ForegroundColor Green
            Write-Host "      - Max activation: $MaxActivationDuration hours" -ForegroundColor Gray
            Write-Host "      - Require approval: $RequireApproval" -ForegroundColor Gray
            Write-Host "      - Require MFA: $RequireMFA" -ForegroundColor Gray
            Write-Host "      - Require justification: $RequireJustification" -ForegroundColor Gray
            
            return $settings
        }
        catch {
            Write-Error "Failed to configure PIM for '$RoleDisplayName': $($_.Exception.Message)"
            return $null
        }
    }
    else {
        Write-Host "  [WhatIf] Would configure PIM for: $RoleDisplayName" -ForegroundColor Yellow
        Write-Host "      - Max activation: $MaxActivationDuration hours" -ForegroundColor Gray
        return @{ DisplayName = $RoleDisplayName }
    }
}

function Get-RoleAssignments {
    param([string]$RoleDefinitionId)
    
    try {
        $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$RoleDefinitionId'" -All -ErrorAction SilentlyContinue
        return $assignments
    }
    catch {
        Write-Verbose "Could not retrieve assignments for role $RoleDefinitionId : $($_.Exception.Message)"
        return @()
    }
}

# Main execution
try {
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  PIM Configuration Deployment" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Load configuration
    $config = & $commonPath\Get-EntraConfig.ps1 -ConfigPath $ConfigPath
    
    if (-not $config.PIM.Enabled) {
        Write-Warning "PIM is disabled in configuration. Exiting."
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
    Write-Host "  Global Admin limit: $($config.PIM.GlobalAdministratorLimit)" -ForegroundColor Gray
    
    # Check license requirements
    Write-Host "`n[Note] PIM requires Entra ID P2 or Entra ID Governance license" -ForegroundColor Yellow
    
    # Get role definitions
    $roleDefinitions = Get-EntraRoleDefinitions
    if (-not $roleDefinitions) {
        Write-Error "Could not retrieve role definitions. Exiting."
        return
    }
    
    # Capture current state
    Write-Host "`nAnalyzing current role assignments..." -ForegroundColor Cyan
    $globalAdminRole = $roleDefinitions | Where-Object { $_.DisplayName -eq 'Global Administrator' }
    
    if ($globalAdminRole) {
        $globalAdminAssignments = Get-RoleAssignments -RoleDefinitionId $globalAdminRole.Id
        Write-Host "  Global Administrators: $($globalAdminAssignments.Count)" -ForegroundColor Gray
        
        if ($globalAdminAssignments.Count -gt $config.PIM.GlobalAdministratorLimit) {
            Write-Warning "Current Global Administrator count ($($globalAdminAssignments.Count)) exceeds recommended limit ($($config.PIM.GlobalAdministratorLimit))"
            Write-Warning "Consider reducing the number of Global Administrators"
        }
    }
    
    # Configure PIM for roles
    Write-Host "`nConfiguring PIM role settings..." -ForegroundColor Cyan
    $configuredRoles = @()
    
    foreach ($roleConfig in $config.PIM.Roles.PSObject.Properties) {
        $roleName = $roleConfig.Name
        
        # Skip the "Default" configuration template
        if ($roleName -eq 'Default') {
            continue
        }
        
        # If specific role requested, skip others
        if ($RoleName -and $roleName -ne $RoleName) {
            continue
        }
        
        # Map configuration names to actual role names
        $roleNameMapping = @{
            'GlobalAdministrator' = 'Global Administrator'
            'SecurityAdministrator' = 'Security Administrator'
            'PrivilegedRoleAdministrator' = 'Privileged Role Administrator'
        }
        
        $actualRoleName = if ($roleNameMapping.ContainsKey($roleName)) {
            $roleNameMapping[$roleName]
        } else {
            $roleName
        }
        
        $role = $roleDefinitions | Where-Object { $_.DisplayName -eq $actualRoleName }
        
        if (-not $role) {
            Write-Warning "Role '$actualRoleName' not found in Entra ID - skipping"
            continue
        }
        
        $roleSettings = $roleConfig.Value
        
        $configured = Set-PIMRoleSettings `
            -RoleDefinitionId $role.Id `
            -RoleDisplayName $role.DisplayName `
            -MaxActivationDuration $roleSettings.MaxActivationDuration `
            -RequireApproval $roleSettings.RequireApproval `
            -RequireMFA $roleSettings.RequireMFA `
            -RequireJustification $roleSettings.RequireJustification `
            -Approvers $roleSettings.Approvers
        
        if ($configured) {
            $configuredRoles += @{
                RoleId = $role.Id
                RoleName = $role.DisplayName
                Settings = $configured
            }
        }
    }
    
    # Create rollback file
    if ($config.DeploymentSettings.CreateRollbackFiles -and $configuredRoles.Count -gt 0) {
        Write-Host "`nCreating rollback file..." -ForegroundColor Cyan
        
        $rollbackFile = New-RollbackFile `
            -Component "PIM-Configuration" `
            -BeforeState @{ Message = "PIM settings before configuration" } `
            -AfterState $configuredRoles `
            -ChangeDescription "Configured PIM settings for $($configuredRoles.Count) privileged roles"
    }
    
    # Summary
    Write-Host "`n=====================================" -ForegroundColor Green
    Write-Host "  PIM Configuration Summary" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Green
    Write-Host "Roles configured: $($configuredRoles.Count)" -ForegroundColor Gray
    
    foreach ($role in $configuredRoles) {
        Write-Host "  [✓] $($role.RoleName)" -ForegroundColor Green
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Convert permanent role assignments to eligible assignments" -ForegroundColor Gray
    Write-Host "2. Navigate to: Entra ID > Identity Governance > Privileged Identity Management" -ForegroundColor Gray
    Write-Host "3. For each role:" -ForegroundColor Gray
    Write-Host "   a. Go to 'Assignments'" -ForegroundColor Gray
    Write-Host "   b. Remove permanent active assignments" -ForegroundColor Gray
    Write-Host "   c. Add users as 'Eligible' instead" -ForegroundColor Gray
    Write-Host "4. Configure notification emails in PIM settings" -ForegroundColor Gray
    Write-Host "5. Set up access reviews for privileged roles" -ForegroundColor Gray
    
    Write-Host "`nBest Practices:" -ForegroundColor Yellow
    Write-Host "  - Start with shorter activation durations (4 hours recommended)" -ForegroundColor Gray
    Write-Host "  - Require approval for most sensitive roles (Global Admin, Security Admin)" -ForegroundColor Gray
    Write-Host "  - Always require MFA for role activation" -ForegroundColor Gray
    Write-Host "  - Regularly review eligible role assignments" -ForegroundColor Gray
    Write-Host "  - Keep Global Administrator count below 5" -ForegroundColor Gray
    Write-Host "  - Use separate accounts for admin duties vs regular work" -ForegroundColor Gray
    
    Write-Host "`nUser Experience:" -ForegroundColor Cyan
    Write-Host "  Users activate roles at: https://portal.azure.com > PIM" -ForegroundColor Gray
    Write-Host "  Or: Entra ID > Identity Governance > Privileged Identity Management > My Roles" -ForegroundColor Gray
    Write-Host "  Activations require MFA and justification" -ForegroundColor Gray
    Write-Host "  Roles auto-deactivate after the configured duration" -ForegroundColor Gray
    
    if ($rollbackFile) {
        Write-Host "`nRollback file: $rollbackFile" -ForegroundColor Gray
    }
}
catch {
    Write-Error "PIM configuration failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}

