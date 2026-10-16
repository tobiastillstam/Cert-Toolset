# Cert-Toolset - project context for Claude Code

PowerShell toolset for certificate management on Windows Server.
Private repo. Owner: Tobias Tillstam / Tillnet. License: MIT.

## Status

- Scaffold only (created 2026-10-16). Existing code from Tobias to be
  brought in and aligned to the house template.

## Coding conventions (house template)

Template: `C:\Users\Tobias\.claude\script_templates\script_template.ps1`
(see the global CLAUDE.md).

- `#Requires -Version 5.1` and `#Requires -RunAsAdministrator`.
- `[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]`.
- Every parameter `[Parameter(Mandatory = $false)]` with a comment above it.
- `.NOTES` block: Author, Webpage, GitHub, Version, Date Created,
  Last Modified, Change Log, Operational notes.
- `# ---...---` section banners; Write-Verbose Starting/Finished bookends.
- Single flat try/catch/finally; catch is `Write-Error $_; throw`.
- Pure ASCII. ShouldProcess only on real state changes.
- Remediation opt-in via named switches, never a catch-all `-Fix`.
- Log/output dirs default to `$PSScriptRoot`, fallback `(Get-Location).Path`.

## Repo hygiene

- `.gitignore` blocks certificate material (*.pfx, *.key, *.pem, *.cer, ...).
  Never commit keys, exported certs or real thumbprints/hostnames from
  client environments.
