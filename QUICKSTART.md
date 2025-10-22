# Entra ID Hardening - Quick Start Guide

This guide will help you get started with the Entra ID hardening scripts in under 15 minutes.

## Prerequisites Checklist

Before you begin, ensure you have:

- [ ] **Global Administrator** or **Security Administrator** role in your Entra ID tenant
- [ ] **Microsoft Entra ID P1 or P2** license (required for Conditional Access and PIM)
- [ ] **PowerShell 7.0+** installed ([Download](https://aka.ms/powershell))
- [ ] **Stable internet connection**
- [ ] **Test environment** (HIGHLY recommended for first-time deployment)

## Step-by-Step Setup

### 1. Install Required PowerShell Modules

Open PowerShell as Administrator and run:

```powershell
# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Install Azure PowerShell modules (for monitoring/logging features)
Install-Module Az.Accounts -Scope CurrentUser -Force
Install-Module Az.Monitor -Scope CurrentUser -Force
Install-Module Az.OperationalInsights -Scope CurrentUser -Force
```

**Time:** ~5 minutes (depending on internet speed)

### 2. Download and Configure

1. **Download/clone this repository** to your local machine

2. **Navigate to the directory:**
   ```powershell
   cd C:\Path\To\Entra-Hardening
   ```

3. **Copy the configuration template:**
   ```powershell
   Copy-Item config.template.json config.json
   ```

4. **Edit config.json** with your organization's details:
   ```powershell
   notepad config.json
   ```

   **Minimum required changes:**
   - `TenantId`: Your Entra ID tenant ID
   - `TenantDomain`: Your `.onmicrosoft.com` domain
   - `OrganizationName`: Your organization name
   - `BreakGlassAccounts.NotificationEmails`: Security team email addresses
   - `TrustedLocations`: Your office IP ranges (if applicable)

**Time:** ~3 minutes

### 3. Connect to Microsoft Graph

```powershell
.\Common\Connect-EntraID.ps1
```

- A browser window will open for authentication
- Sign in with your Global Administrator account
- Consent to the requested permissions
- Close the browser when prompted

**Time:** ~2 minutes

### 4. Validate Configuration

```powershell
.\Common\Get-EntraConfig.ps1 -ValidateOnly
```

Ensure there are no validation errors before proceeding.

**Time:** ~30 seconds

## Deployment Options

### Option A: Phased Deployment (Recommended)

Deploy in phases to minimize risk and allow for testing:

#### Phase 1: Immediate Actions (Week 1-2)
```powershell
.\Deploy-EntraHardening.ps1 -Phase 1 -WhatIf
# Review the output, then run without -WhatIf:
.\Deploy-EntraHardening.ps1 -Phase 1
```

**What this does:**
- Creates break-glass emergency accounts
- Enables MFA for administrators
- Blocks legacy authentication (report-only mode)
- Creates trusted network locations
- Sets up emergency CA policies (disabled)

**Critical follow-up:** Secure break-glass credentials physically!

#### Phase 2: Core Hardening (Month 1)
```powershell
.\Deploy-EntraHardening.ps1 -Phase 2
```

**What this does:**
- Rolls out MFA to all users
- Deploys baseline Conditional Access policies
- Configures PIM for privileged roles
- Sets up audit logging
- Restricts application consent

#### Phase 3: Advanced Security (Month 2-3)
```powershell
.\Deploy-EntraHardening.ps1 -Phase 3
```

**What this does:**
- Enables passwordless authentication
- Hardens B2B collaboration
- Deploys password protection
- Audits enterprise applications

### Option B: Individual Modules

Run specific modules as needed:

```powershell
# MFA only
.\Modules\1-MFA-Authentication\Deploy-MFA.ps1 -WhatIf

# Conditional Access only
.\Modules\2-ConditionalAccess\Deploy-BaselineCA.ps1 -WhatIf

# Break-glass accounts only
.\Modules\4-BreakGlass\New-BreakGlassAccount.ps1 -WhatIf
```

### Option C: Full Deployment (Advanced Users Only)

```powershell
.\Deploy-EntraHardening.ps1 -Phase All
```

⚠️ **Warning:** This deploys all security controls at once. Only use in test environments or if you've thoroughly reviewed all configurations.

## Post-Deployment Checklist

After completing Phase 1, ensure you:

- [ ] **Secure break-glass credentials** in physical safes (separate locations)
- [ ] **Document storage locations** and access procedures
- [ ] **Test break-glass account** access
- [ ] **Monitor Conditional Access** policies in report-only mode for 7 days
- [ ] **Review sign-in logs** for policy impact
- [ ] **Communicate changes** to users and IT team

## Verification

### Check Security Posture
```powershell
.\Get-SecurityPosture.ps1 -ExportReport
```

This generates a comprehensive report showing your current security score and recommendations.

### Monitor Break-Glass Accounts
```powershell
.\Modules\4-BreakGlass\Monitor-BreakGlassActivity.ps1
```

Schedule this to run daily to detect any emergency account usage.

### Audit Applications
```powershell
.\Modules\6-ApplicationSecurity\Audit-EnterpriseApps.ps1 -ExportReport
```

Review and remove suspicious or unnecessary applications.

## Troubleshooting

### "Not connected to Microsoft Graph"
```powershell
.\Common\Connect-EntraID.ps1
```

### "Insufficient permissions"
Ensure your account has:
- Global Administrator OR
- Security Administrator + Conditional Access Administrator + Privileged Role Administrator

### "Module not found"
Ensure you're running from the root directory of the repository:
```powershell
cd C:\Path\To\Entra-Hardening
```

### Policies not enforcing
Check if policies are in report-only mode:
```powershell
Get-MgIdentityConditionalAccessPolicy -All | 
    Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' } |
    Select-Object DisplayName, State
```

## Best Practices

1. **Always test in a non-production environment first**
2. **Use -WhatIf flag** to preview changes before applying
3. **Deploy in phases** rather than all at once
4. **Monitor impact** for 7 days before enforcing policies
5. **Communicate changes** to users in advance
6. **Keep break-glass credentials secure and tested**
7. **Review logs regularly** after deployment

## Getting Help

### Check the Logs
```powershell
Get-Content .\Logs\EntraHardening-$(Get-Date -Format 'yyyyMMdd').log -Tail 50
```

### Common Issues and Solutions

**Issue:** MFA policies block legitimate access
- **Solution:** Review exclusions in config.json, ensure break-glass accounts are excluded

**Issue:** Legacy auth policy breaks email clients
- **Solution:** Keep policy in report-only mode longer, update clients to modern auth

**Issue:** Too many Global Administrators
- **Solution:** Review assignments, convert to eligible in PIM, remove unnecessary assignments

## Next Steps

1. **Complete Phase 1** and wait 1-2 weeks
2. **Review sign-in logs** and policy impact
3. **Adjust configurations** based on findings
4. **Proceed to Phase 2** when ready
5. **Schedule regular reviews:**
   - Daily: Break-glass monitoring
   - Weekly: Sign-in log review
   - Monthly: Application audit
   - Quarterly: Security posture assessment, access reviews

## Support and Documentation

- **Full Documentation:** See [README.md](README.md)
- **Microsoft Entra Docs:** https://learn.microsoft.com/en-us/entra/
- **Conditional Access:** https://learn.microsoft.com/en-us/entra/identity/conditional-access/
- **PIM Documentation:** https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/

## Important Reminders

- 🔐 **Secure break-glass credentials physically**
- 📋 **Document all changes and procedures**
- 👥 **Train security team on emergency procedures**
- 🔄 **Test emergency access quarterly**
- 📊 **Monitor and adjust policies regularly**
- ⚠️ **Never skip testing in production deployments**

---

**Estimated Total Time for Phase 1:** 30-45 minutes (excluding monitoring period)

**Congratulations!** You're now on the path to a more secure Entra ID environment. 🎉

