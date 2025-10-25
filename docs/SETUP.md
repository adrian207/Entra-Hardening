# Setup & Next Steps for Entra-Hardening

This document describes the recommended repository settings, topics (tags), and the automation added to this repo.

## GitHub Pages

The repository includes `docs/index.md` which can be served by GitHub Pages.

To enable Pages:

1. Go to the repository Settings → Pages.
2. Under "Source" choose branch `main` and folder `/docs`.
3. Save. Wait a few minutes for the site to publish.

Your site will be available at:
`https://<your-user-or-org>.github.io/Entra-Hardening/`

## Repository topics (tags)

Suggested topics (use one or more):

- azure-ad
- entra
- microsoft-entra
- azure-security
- security-hardening
- powershell
- mfa
- conditional-access
- pim
- b2b
- password-protection
- audit-logging
- application-security
- automation

Set topics using the GitHub CLI (recommended):

```bash
gh repo edit adrian207/Entra-Hardening --add-topic azure-ad --add-topic entra --add-topic microsoft-entra --add-topic azure-security --add-topic security-hardening --add-topic powershell --add-topic mfa --add-topic conditional-access --add-topic pim --add-topic b2b --add-topic password-protection --add-topic audit-logging --add-topic application-security --add-topic automation
```

Or, use the GitHub REST API (token required):

```bash
export GITHUB_TOKEN="YOUR_TOKEN"
curl -X PUT -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/adrian207/Entra-Hardening/topics -d '{"names":["azure-ad","entra","microsoft-entra","azure-security","security-hardening","powershell","mfa","conditional-access","pim","b2b","password-protection","audit-logging","application-security","automation"]}'
```

## Automation added

- `.github/workflows/create-labels.yml` — creates or updates labels defined in `.github/labels.yml`. You can run it manually from the Actions tab (workflow_dispatch) or let it run on push to `main`.
- `.github/workflows/powershell-lint.yml` — a lightweight CI job that runs `PSScriptAnalyzer` against `Modules/` and `Common/` and fails on `Error` severity findings.

## How labels are created

The `create-labels` workflow reads `.github/labels.yml` and calls the Issues API to create or update labels. If you'd like to change label colors or add more labels, edit `.github/labels.yml` and push to `main` or run the workflow manually.

## Optional improvements you might want

- Fail the lint job on warnings (change the workflow to exit 1 on warnings).
- Add a GitHub Pages CI pipeline (e.g., MkDocs) if you want richer docs with navigation.
- Add automated releases and changelog generation.
- Add a Dependabot configuration to keep modules and actions up to date.

## Security contact

Please update `SECURITY.md` with a working contact email for private vulnerability reports.
