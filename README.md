# Microsoft Entra ID Hardening Scripts

A modular, client-agnostic PowerShell toolkit for implementing Microsoft Entra ID (Azure AD) security hardening based on Microsoft's official guidance and industry best practices.

## Overview

This toolkit provides automated scripts to implement comprehensive Entra ID security controls across 10 major security areas. Each module is independent and can be executed individually, allowing organizations to implement hardening controls at their own pace.

## Features

- **Modular Design**: Pick and choose which security controls to implement
- **Client-Agnostic**: Configuration-driven approach works with any tenant
- **Report-Only Mode**: Test policies before enforcement
- **Rollback Support**: Safely revert changes if needed
- **Comprehensive Logging**: Track all changes and operations
- **Best Practices**: Based on official Microsoft guidance

## Prerequisites

### Required Licenses
- Microsoft Entra ID P1 (minimum for Conditional Access)
- Microsoft Entra ID P2 (for risk-based policies and PIM)
- Microsoft Entra ID Governance (optional, for advanced PIM features)

### Required PowerShell Modules
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module Az.Accounts -Scope CurrentUser -Force
Install-Module Az.Monitor -Scope CurrentUser -Force
```

### Required Permissions
The account running these scripts needs:
- Global Administrator (for full implementation)
- Security Administrator (for read-only audits)
- Conditional Access Administrator (for CA policies only)
- Privileged Role Administrator (for PIM configuration)

## Quick Start

1. **Clone or download this repository**

2. **Configure your environment**
   ```powershell
   # Copy the template configuration
   Copy-Item config.template.json config.json
   
   # Edit config.json with your organization's settings
   notepad config.json
   ```

3. **Connect to Microsoft Graph**
   ```powershell
   .\Common\Connect-EntraID.ps1
   ```

4. **Run individual modules or use the orchestrator**
   ```powershell
   # Run individual module
   .\Modules\1-MFA-Authentication\Deploy-MFA.ps1 -WhatIf
   
   # Run orchestrator for full deployment
   .\Deploy-EntraHardening.ps1 -Phase 1 -WhatIf
   ```

## Module Structure

### Module 1: Identity Protection & Authentication
- **Deploy-MFA.ps1**: Enforce MFA for all users
- **Deploy-PasswordlessAuth.ps1**: Configure passwordless authentication methods
- **Block-LegacyAuth.ps1**: Disable legacy authentication protocols

### Module 2: Conditional Access Policies
- **Deploy-BaselineCA.ps1**: Deploy baseline Conditional Access policies
- **Deploy-RiskBasedCA.ps1**: Implement risk-based access controls
- **New-EmergencyCAPolicy.ps1**: Create emergency access policies

### Module 3: Privileged Identity Management
- **Deploy-PIM.ps1**: Configure PIM for privileged roles
- **Set-JITAccess.ps1**: Implement Just-In-Time access
- **Review-PrivilegedAccess.ps1**: Audit privileged role assignments

### Module 4: Break-Glass Accounts
- **New-BreakGlassAccount.ps1**: Create emergency access accounts
- **Monitor-BreakGlassActivity.ps1**: Alert on emergency account usage

### Module 5: Identity Governance
- **Deploy-AccessReviews.ps1**: Configure automated access reviews
- **Audit-LeastPrivilege.ps1**: Review and enforce least privilege

### Module 6: Monitoring & Auditing
- **Deploy-AuditLogging.ps1**: Configure audit log retention and streaming
- **Deploy-SIEMIntegration.ps1**: Integrate with external SIEM
- **New-SecurityAlerts.ps1**: Create custom security alerts

### Module 7: Application Security
- **Restrict-AppConsent.ps1**: Disable user app consent
- **Audit-EnterpriseApps.ps1**: Review registered applications
- **Restrict-AppRegistration.ps1**: Limit app registration permissions

### Module 8: External Collaboration & Network
- **Harden-B2BSettings.ps1**: Secure external collaboration
- **Deploy-NamedLocations.ps1**: Configure trusted network locations
- **Disable-WeakProtocols.ps1**: Disable weak ciphers and protocols

### Module 9: Password Protection
- **Deploy-PasswordProtection.ps1**: Enable banned password lists
- **Set-PasswordPolicy.ps1**: Configure strong password requirements

### Module 10: Reporting & Compliance
- **Get-SecurityPosture.ps1**: Generate comprehensive security reports
- **Export-ComplianceReport.ps1**: Create audit documentation

## Configuration

The `config.json` file drives all module behavior. Key sections:

```json
{
  "TenantId": "your-tenant-id",
  "OrganizationName": "Client Name",
  "BreakGlassAccounts": {
    "Count": 2,
    "PasswordLength": 32
  },
  "ConditionalAccess": {
    "ReportOnlyDuration": 7,
    "TrustedLocations": []
  },
  "PIM": {
    "DefaultActivationDuration": 4,
    "RequireApproval": true
  }
}
```

## Implementation Phases

### Phase 1 - Immediate Actions (Week 1-2)
```powershell
.\Deploy-EntraHardening.ps1 -Phase 1 -WhatIf
```
- Create break-glass accounts
- Enable MFA for administrators
- Block legacy authentication
- Deploy baseline CA policies (report-only)

### Phase 2 - Core Hardening (Month 1)
```powershell
.\Deploy-EntraHardening.ps1 -Phase 2
```
- Roll out MFA to all users
- Enforce Conditional Access policies
- Implement PIM for Global Administrators
- Set up audit log retention

### Phase 3 - Advanced Security (Month 2-3)
```powershell
.\Deploy-EntraHardening.ps1 -Phase 3
```
- Deploy passwordless authentication
- Implement risk-based Conditional Access
- Extend PIM to all privileged roles
- Integrate with SIEM

### Phase 4 - Continuous Improvement (Ongoing)
- Regular access reviews
- Policy refinement
- Security posture assessments

## Safety Features

### WhatIf Mode
All scripts support `-WhatIf` to preview changes without applying them:
```powershell
.\Modules\2-ConditionalAccess\Deploy-BaselineCA.ps1 -WhatIf
```

### Report-Only First
Conditional Access policies are deployed in report-only mode by default, with automatic enforcement after the configured duration.

### Rollback Support
All scripts create rollback files in the `Rollback\` directory:
```powershell
.\Rollback\Restore-Changes.ps1 -RollbackFile ".\Rollback\20250122-143022-Deploy-BaselineCA.json"
```

## Logging

All operations are logged to `Logs\` directory with timestamps:
- `Logs\EntraHardening-YYYYMMDD.log`: Main execution log
- `Logs\Changes-YYYYMMDD.json`: Detailed change tracking
- `Logs\Errors-YYYYMMDD.log`: Error log

## Support & Documentation

- [Microsoft Entra Documentation](https://learn.microsoft.com/en-us/entra/)
- [Conditional Access Planning](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [PIM Deployment Guide](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-deployment-plan)

## Security Considerations

- **Test in Non-Production First**: Always validate in a test tenant
- **Review Exclusions**: Minimize CA policy exclusions
- **Protect Break-Glass Accounts**: Follow physical security procedures
- **Monitor Break-Glass Usage**: Alert on any emergency account activity
- **Regular Reviews**: Conduct periodic access reviews

## Contributing

This toolkit is designed to be extended. To add custom modules:
1. Create a new folder under `Modules\`
2. Follow the existing module structure
3. Use shared utilities from `Common\`
4. Update `config.template.json` with new settings

## License

This project is provided as-is for security hardening purposes.

## Disclaimer

[Unverified] These scripts make significant changes to your Entra ID tenant. Always:
- Test in a non-production environment first
- Review all configurations before deployment
- Ensure you have valid break-glass account access
- Maintain backups of current configurations
- Have rollback procedures ready

