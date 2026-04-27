# Policy GitOps

**This plugin has been moved to its own repository:**

**https://github.com/alexgoller/illumio-policy-gitops**

The standalone project includes:
- `plugin/` — The plugger plugin (PCE↔Git sync engine)
- `action/scripts/` — Security check + traffic evidence pipeline
- `template/` — Starter policy repo with workflows, CODEOWNERS, config
- Full documentation (1500+ lines)

## Install via Plugger

```bash
plugger install ghcr.io/alexgoller/illumio-policy-gitops:latest
```

## Why Standalone?

Policy GitOps is more than a plugin — it's a workflow system that spans the customer's policy Git repo, GitHub Actions pipelines, and the PCE. The GitHub Actions, security rules, CODEOWNERS templates, and PR visualization live in the customer's repo, not in plugger.
