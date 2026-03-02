# 🔑 CloudKeyRotator

> **Multi-Cloud Credential Exposure Validator**
> 
> Paste a leaked credential → auto-detect the provider → validate if it's still active → enumerate permissions → assess blast radius → get remediation steps.

```
██████╗██╗      ██████╗ ██╗   ██╗██████╗    ██╗  ██╗███████╗██╗   ██╗
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗   ██║ ██╔╝██╔════╝╚██╗ ██╔╝
██║     ██║     ██║   ██║██║   ██║██║  ██║   █████╔╝ █████╗   ╚████╔╝ 
██║     ██║     ██║   ██║██║   ██║██║  ██║   ██╔═██╗ ██╔══╝    ╚██╔╝  
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝   ██║  ██╗███████╗   ██║   
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝   ╚═╝  
██████╗  ██████╗ ████████╗ █████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔═══██╗╚══██╔══╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝██║   ██║   ██║   ███████║   ██║   ██║   ██║██████╔╝
██╔══██╗██║   ██║   ██║   ██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║╚██████╔╝   ██║   ██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

---

## ✨ Features

| Feature | Details |
|---------|---------|
| **Auto-detection** | Identifies AWS, Azure, GCP, GitHub credentials from format/pattern alone |
| **Live validation** | Calls provider APIs to confirm if the key is still active |
| **Permission enumeration** | Discovers what actions/services the credential can access |
| **Blast radius assessment** | Rates severity (CRITICAL/HIGH/MEDIUM/LOW) and summarises damage potential |
| **Remediation guide** | CLI commands and portal links to revoke the credential |
| **Multiple output formats** | Rich table, JSON, Markdown |
| **Pipe-friendly** | Works in pipelines: `echo "ghp_xxx" \| ckr scan` |

### Supported Providers

| Provider | Credential Types |
|----------|-----------------|
| **AWS** | Access Key ID + Secret, Temporary STS credentials (ASIA...) |
| **Azure** | Client Secrets, Storage Connection Strings, SAS Tokens |
| **GCP** | Service Account JSON keys |
| **GitHub** | Classic PATs (`ghp_`), Fine-Grained PATs (`github_pat_`), OAuth/Actions tokens |
| **Generic** | Probes 10+ common APIs (Slack, Stripe, DigitalOcean, Cloudflare...) as fallback |

---

## 🚀 Installation

```bash
# Clone
git clone https://github.com/you/cloudkeyrotator.git
cd cloudkeyrotator

# Install with all provider SDKs (recommended)
pip install -e ".[all]"

# Or install with specific provider support
pip install -e ".[aws]"
pip install -e ".[azure]"
pip install -e ".[gcp]"

# Core only (GitHub + generic probes work without extra SDKs)
pip install -e .
```

A short alias `ckr` is also registered:

```bash
ckr --help
```

---

## 📖 Usage

### `scan` — Validate a credential

```bash
# AWS Access Key (will prompt for secret key)
ckr scan AKIAIOSFODNN7EXAMPLE

# GitHub PAT
ckr scan ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# GCP Service Account JSON file
ckr scan --file /path/to/sa-key.json

# Azure Client Secret (tenant + client ID required)
ckr scan MyS3cr3tV@lue \
  --tenant-id 72f988bf-0000-1111-2222-2d7cd011db47 \
  --client-id 1d2e3f4a-0000-1111-2222-3b4c5d6e7f8a

# Pipe a credential from stdin
echo "ghp_xxxx" | ckr scan

# Output as JSON (for scripting)
ckr scan AKIAIOSFODNN7EXAMPLE --output json

# Save a Markdown report
ckr scan ghp_xxxx --output markdown --out-file report.md

# Skip permission enumeration (faster, no additional API calls)
ckr scan ghp_xxxx --skip-enum
```

### `detect` — Identify type without network calls

```bash
ckr detect AKIAIOSFODNN7EXAMPLE
# → Provider: AWS | Type: aws_access_key | Confidence: high

ckr detect ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# → Provider: GitHub | Type: github_pat | Confidence: high
```

### `revoke-guide` — Step-by-step revocation instructions

```bash
ckr revoke-guide aws
ckr revoke-guide azure
ckr revoke-guide gcp
ckr revoke-guide github
```

---

## 🎨 Sample Output

```
╭─────────────────────────────────────────╮
│         CloudKeyRotator v1.0.0          │
│   Multi-Cloud Credential Exposure       │
│   Validator                             │
╰─────────────────────────────────────────╯

╭──── 🔍 Credential Detected ─────────────╮
│ Provider:  GitHub                       │
│ Type:      github_pat                   │
│ Pattern:   GitHub Classic PAT           │
╰─────────────────────────────────────────╯

╭──── GitHub — personal_access_token ─────╮
│         ✔  CREDENTIAL VALID             │
╰─────────────────────────────────────────╯

 Identity                                  
┌──────────────────────┬───────────────────┐
│ Field                │ Value             │
├──────────────────────┼───────────────────┤
│ Login                │ octocat           │
│ Name                 │ The Octocat       │
│ Company              │ GitHub            │
│ Public Repos         │ 8                 │
│ Two Fa               │ True              │
└──────────────────────┴───────────────────┘

 Blast Radius Assessment  🔴 HIGH           
┌──────────────────────────────┬────────────┐
│ Critical Scopes              │ • repo     │
│ Org Count                    │ 2          │
│ Private Repos Accessible     │ 47         │
└──────────────────────────────┴────────────┘

╭── Summary ──────────────────────────────────────────────────────────╮
│ 🔴 Full repo scope + 47 private repo(s). Source code, secrets and   │
│ deployment keys at risk.                                             │
╰─────────────────────────────────────────────────────────────────────╯

╭── ⚠  Remediation ─────────────────────────────────────────────────╮
│ Revoke Url: https://github.com/settings/tokens                     │
╰────────────────────────────────────────────────────────────────────╯
```

---

## 🏗️ Architecture

```
cloudkeyrotator/
├── cli.py          ← Click CLI: scan / detect / revoke-guide commands
├── detector.py     ← Regex + JSON pattern matching (zero network calls)
├── reporter.py     ← Rich table, JSON, and Markdown formatters
└── validators/
    ├── base.py     ← BaseValidator ABC
    ├── aws.py      ← boto3 + STS + IAM SimulatePrincipalPolicy
    ├── azure.py    ← OAuth2 client credentials + Graph/ARM API probes
    ├── gcp.py      ← google-auth SA + GCP API probes
    ├── github.py   ← GitHub REST API + scope analysis
    └── generic.py  ← Probes 10+ APIs as provider-agnostic fallback
```

### How the blast-radius engine works

```
Credential input
      │
      ▼
  detector.py          ← Pattern match / JSON parse
  (zero network)
      │
      ▼
  ValidatorClass        ← validate()
  .validate()              Calls minimum auth endpoint to confirm liveness
      │
      ▼
  .enumerate()          ← Additional API calls to map accessible services
      │                    Runs IAM simulation / scope analysis
      ▼
  Severity rating       CRITICAL / HIGH / MEDIUM / LOW
  + Summary
      │
      ▼
  reporter.py           ← Rich table / JSON / Markdown
```

---

## ⚙️ Environment Variables

| Variable | Description |
|----------|-------------|
| `CKR_NO_BANNER` | Set to `1` to suppress banner |
| `CKR_TIMEOUT` | HTTP timeout in seconds (default: `10`) |

---

## 🔒 Security & Ethics

> **This tool is for authorized security testing and incident response only.**
> 
> - Only scan credentials you own or have explicit written authorization to test.
> - Treat output as sensitive — it may confirm active access to production systems.
> - Report and revoke exposed credentials immediately; do not use them for unauthorized access.

This tool makes **read-only** API calls for enumeration. It does **not** create resources, modify data, or exfiltrate anything.

**MITRE ATT&CK coverage:** T1552 (Unsecured Credentials), T1078 (Valid Accounts), T1613 (Container and Resource Discovery)

---

## 📋 License

MIT — see [LICENSE](LICENSE).

---

## 🤝 Contributing

Issues and PRs welcome. When adding a new provider:

1. Add detection patterns to `detector.py`
2. Create `validators/<provider>.py` inheriting `BaseValidator`
3. Register in `cli.py`'s `VALIDATOR_MAP`
4. Add revocation guide to the `revoke-guide` command
