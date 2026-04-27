# Illumio Policy Repository

This repository manages Illumio PCE segmentation policy as code.

## How It Works

1. Policy is defined as YAML files organized by scope (application + environment)
2. Changes are proposed via Pull Requests
3. GitHub Actions validates changes: YAML lint, security checks, traffic evidence
4. CODEOWNERS ensures the right teams review changes to their scopes
5. On merge to main, policy is provisioned to the PCE

## Structure

```
scopes/                  Each team's policy scope
├── _global/             Unscoped rulesets (e.g., coreservices)
├── payments-prod/       Team A's scope
│   ├── _scope.yaml      Scope definition (labels)
│   ├── intra-rules.yaml Intra-scope rules
│   └── cross-scope/     Rules requiring other team's approval
├── shareddb-prod/       Team B's scope
│   ├── _scope.yaml
│   └── inbound/         Approved inbound cross-scope rules
ip-lists/                Shared IP lists
services/                Service definitions
```

## Making Changes

1. Create a branch
2. Edit or add YAML files in the appropriate scope directory
3. Open a PR — the pipeline will validate and post a report
4. Get reviews from required teams (CODEOWNERS enforced)
5. Merge — policy provisions to PCE automatically

## Cross-Scope Rules

If your rule needs to reach another team's application:
1. Add the rule definition in `your-scope/cross-scope/to-{target}.yaml`
2. Add a mirror in `target-scope/inbound/from-{your-scope}.yaml`
3. CODEOWNERS will require the target team's review
4. The PR comment shows traffic evidence proving the rule is needed

## Security Checks

The pipeline evaluates every change against `.illumio/security-rules.yaml`:
- **Critical** (blocks PR): any-to-any rules, broad port ranges, insecure protocols
- **High** (warning): cross-scope without justification, RDP/SMB, unscoped DB access
- **Medium** (info): broad CIDRs, HTTP without HTTPS

## Traffic Evidence

The pipeline queries the PCE for blocked traffic matching each new rule.
If traffic exists, the rule is marked "Justified" in the PR comment.
If no traffic is found, it's flagged for review.
