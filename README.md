# Entra-Hardening

PowerShell scripts that apply Microsoft Entra ID security baselines through Microsoft Graph: MFA, legacy authentication blocking, Conditional Access, PIM, break-glass accounts, audit logging, app consent, B2B settings and password protection. Settings come from one JSON config file, and every change script supports `-WhatIf`.

## What it does

Scripts are grouped by area under `Modules/` and can run on their own or in phases through `Deploy-EntraHardening.ps1`.

| Phase | Scripts run |
|---|---|
| **1: Immediate** | `New-BreakGlassAccount`, `Deploy-MFA`, `Block-LegacyAuth`, `Deploy-NamedLocations`, `New-EmergencyCAPolicy` |
| **2: Core** | `Deploy-MFA`, `Deploy-BaselineCA`, `Deploy-PIM`, `Deploy-AuditLogging`, `Restrict-AppConsent` |
| **3: Advanced** | `Deploy-PasswordlessAuth`, `Harden-B2BSettings`, `Deploy-PasswordProtection`, `Audit-EnterpriseApps` |

Also included:

- `Get-SecurityPosture.ps1`: read-only report of current settings with recommendations
- `Modules/4-BreakGlass/Monitor-BreakGlassActivity.ps1`: checks sign-ins by break-glass accounts
- `Common/New-RollbackFile.ps1`: records before/after state for changes

Conditional Access policies from `Deploy-BaselineCA.ps1` are created in **report-only** mode unless you pass `-EnforceImmediately`.

## Requirements

- PowerShell 7 or Windows PowerShell 5.1
- Microsoft Graph PowerShell SDK (`Microsoft.Graph`). `Deploy-AuditLogging.ps1` also needs `Az.Monitor` and `Az.OperationalInsights`
- Entra ID P1 for Conditional Access; P2 for PIM and risk-based controls
- An account that can consent to the Graph scopes requested by `Common/Connect-EntraID.ps1` (including `Policy.ReadWrite.ConditionalAccess`, `RoleManagement.ReadWrite.Directory` and `Directory.ReadWrite.All`)

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az.Accounts, Az.Monitor, Az.OperationalInsights -Scope CurrentUser   # only for audit logging
```

## Quick start

```powershell
git clone https://github.com/adrian207/Entra-Hardening.git
cd Entra-Hardening

# 1. Create your config from the template and fill in tenant details
Copy-Item config.template.json config.json

# 2. Connect to Microsoft Graph
.\Common\Connect-EntraID.ps1

# 3. See where the tenant stands today (read-only)
.\Get-SecurityPosture.ps1

# 4. Preview phase 1, then apply it
.\Deploy-EntraHardening.ps1 -Phase 1 -WhatIf
.\Deploy-EntraHardening.ps1 -Phase 1
```

Scripts read `config.json` from the repository root and fall back to `config.template.json` if it doesn't exist. Pass `-ConfigPath` to use another file.

Create and test break-glass accounts before enforcing any Conditional Access policy.

## Repository layout

```
Deploy-EntraHardening.ps1   Phased runner (-Phase 1 | 2 | 3 | All)
Get-SecurityPosture.ps1     Read-only posture report
Common/                     Graph connection, config loader, logging, rollback records
Modules/1-MFA-Authentication/  2-ConditionalAccess/  3-PIM/  4-BreakGlass/
        5-Monitoring/  6-ApplicationSecurity/  7-ExternalCollaboration/  8-PasswordProtection/
config.template.json        All settings
docs/                       Setup guide
```

## Documentation

- [QUICKSTART.md](QUICKSTART.md)
- [docs/SETUP.md](docs/SETUP.md)
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT. See [LICENSE.md](LICENSE.md).

## Author

Adrian Johnson · [github.com/adrian207](https://github.com/adrian207)
