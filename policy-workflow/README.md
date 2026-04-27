# Policy Workflow

**This plugin has been moved to the Policy GitOps project:**

**https://github.com/alexgoller/illumio-policy-gitops** (see `workflow/` directory)

The standalone project includes both:
- `plugin/` — Policy GitOps (PCE↔Git sync, YAML export, drift detection)
- `workflow/` — Policy Workflow (change detection, risk classification, approval routing)

## Install via Plugger

```bash
plugger install ghcr.io/alexgoller/illumio-policy-workflow:latest
```

## Why Combined?

Both plugins solve the same core problem — policy governance — from different angles. GitOps suits Git-native teams, Workflow suits ITSM-native teams. They share the same design docs, testing plans, and scope concepts.
