# Changelog

All notable changes to the Entra ID Hardening Scripts project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-22

### Initial Release

#### Added

**Core Infrastructure:**
- Main orchestration script (`Deploy-EntraHardening.ps1`) with phased deployment
- Configuration management system (`config.json` / `config.template.json`)
- Common utilities for connection, logging, and rollback
- Security posture assessment tool (`Get-SecurityPosture.ps1`)

**Module 1: MFA & Authentication**
- `Deploy-MFA.ps1` - Multi-factor authentication enforcement
- `Deploy-PasswordlessAuth.ps1` - Passwordless authentication configuration
- `Block-LegacyAuth.ps1` - Legacy protocol blocking

**Module 2: Conditional Access**
- `Deploy-BaselineCA.ps1` - Baseline Conditional Access policies
- `Deploy-NamedLocations.ps1` - Trusted network location configuration
- `New-EmergencyCAPolicy.ps1` - Emergency access policies

**Module 3: Privileged Identity Management**
- `Deploy-PIM.ps1` - PIM configuration for privileged roles

**Module 4: Break-Glass Accounts**
- `New-BreakGlassAccount.ps1` - Emergency access account creation
- `Monitor-BreakGlassActivity.ps1` - Break-glass usage monitoring

**Module 5: Monitoring & Auditing**
- `Deploy-AuditLogging.ps1` - Audit log configuration and retention

**Module 6: Application Security**
- `Restrict-AppConsent.ps1` - Disable user application consent
- `Audit-EnterpriseApps.ps1` - Application security audit

**Module 7: External Collaboration**
- `Harden-B2BSettings.ps1` - B2B collaboration security

**Module 8: Password Protection**
- `Deploy-PasswordProtection.ps1` - Banned password lists and smart lockout

**Documentation:**
- Comprehensive README.md with full project documentation
- QUICKSTART.md for rapid deployment
- CHANGELOG.md for version tracking
- Inline script documentation and help text

**Features:**
- WhatIf support for safe testing
- Report-only mode for Conditional Access policies
- Automatic rollback file generation
- Comprehensive logging
- Phased deployment approach (Phase 1, 2, 3, All)
- Client-agnostic configuration
- Modular architecture for pick-and-choose deployment

### Security Considerations

This initial release implements:
- Break-glass emergency access accounts
- Multi-factor authentication enforcement
- Legacy authentication blocking
- Conditional Access baseline policies
- Privileged Identity Management
- Application consent restrictions
- B2B collaboration hardening
- Password protection and smart lockout
- Comprehensive audit logging
- Security posture assessment

### Known Limitations

- Some features require manual configuration in Azure Portal (noted in scripts)
- PIM role settings configuration requires appropriate Graph API permissions
- Diagnostic settings for audit logging require Azure Portal configuration
- SIEM integration setup is guidance-only (requires external systems)
- License requirements: Entra ID P1/P2 for advanced features

### Requirements

- PowerShell 7.0 or higher
- Microsoft.Graph PowerShell modules
- Az.Accounts, Az.Monitor, Az.OperationalInsights modules (for logging features)
- Entra ID P1 license (minimum) or P2 (recommended)
- Global Administrator or equivalent permissions

### Migration Notes

This is the initial release - no migration needed.

## [Unreleased]

### Planned Features
- Automated policy enforcement after report-only period
- Integration with Microsoft Sentinel
- Advanced analytics and reporting
- Automated access review creation
- Compliance report generation
- PowerShell Gallery publication
- CI/CD integration examples
- Docker containerization for automation

---

## Version History

- **1.0.0** (2025-10-22) - Initial release with full module suite

## Reporting Issues

Please report issues, bugs, or feature requests through:
- GitHub Issues (if hosted on GitHub)
- Your organization's internal ticketing system
- Direct contact with the security team

## Contributing

Contributions should follow:
1. Test in non-production environment
2. Follow existing code style and patterns
3. Update documentation
4. Add entries to CHANGELOG.md
5. Ensure backward compatibility

