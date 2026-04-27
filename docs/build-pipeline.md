# Build Pipeline & Versioning

How plugins are built, versioned, and released across the Plugger ecosystem.

## Architecture

```
Developer                    GitHub Actions                   GHCR
────────                    ──────────────                   ────
                                                             
  git push main ──────────▶ build.yml triggers               
                            │                                
                            ├─ docker job (15 plugins)       
                            │  matrix: parallel builds       
                            │  buildx: amd64 + arm64         
                            │  push to GHCR ─────────────▶  ghcr.io/alexgoller/
                            │                                  plugger-{name}:latest
                            │                                
                            ├─ cli job (4 platforms)          
                            │  go build: linux/darwin         
                            │  × amd64/arm64                 
                            │  upload artifacts              
                            │                                
  git tag v0.3.0 ─────────▶ all above + release job          
                            │  create GitHub Release         
                            │  attach CLI binaries           
                            │  tag images: 0.3.0, 0.3       
                            │                                
  push to docs/portal/ ───▶ pages.yml triggers               
                            │  deploy to GitHub Pages        
```

## Versioning

### Semver: MAJOR.MINOR.PATCH

| Bump | When | Example |
|------|------|---------|
| **PATCH** | Bug fix, typo, log change — no behavior change | 0.1.0 → 0.1.1 |
| **MINOR** | New feature, new config, new endpoint — backward compatible | 0.1.0 → 0.2.0 |
| **MAJOR** | Breaking change — YAML format, removed config, API change | 0.2.0 → 1.0.0 |

**Default:** bump MINOR on every meaningful change. PATCH for trivial fixes. MAJOR only on explicit decision.

### Where versions live

| Location | What it controls | Updated by |
|----------|-----------------|------------|
| `{plugin}/plugin.yaml` → `version:` | Version shown at install time | Developer (manual) |
| `{plugin}/.plugger/metadata.yaml` → `info.version:` | Version baked into Docker image | Dockerfile `ARG VERSION` |
| Docker image tag | `ghcr.io/.../plugger-{name}:0.3.0` | CI pipeline |
| `docs/portal/registry.json` → `version:` | Version shown on portal | Developer (manual) |
| Git tag | `v0.3.0` triggers release | Developer (`git tag`) |

### Version injection

Each plugin Dockerfile accepts a `VERSION` build arg:

```dockerfile
ARG VERSION=0.1.0
RUN sed -i "s/^  version: .*/  version: \"${VERSION}\"/" /.plugger/metadata.yaml || true
```

The CI pipeline passes the version automatically:
- **Tagged build** (`v0.3.0`): `VERSION=v0.3.0`
- **Branch build** (push to main): `VERSION=0.1.0-dev`
- **Local build** (no arg): `VERSION=0.1.0` (default)

## Building Locally

### Single plugin

```bash
cd ai-security-report
docker build -t plugger-ai-security-report:latest .

# With explicit version
docker build --build-arg VERSION=0.2.0 -t plugger-ai-security-report:0.2.0 .
```

### Install locally built image

```bash
plugger install plugin.yaml
plugger start ai-security-report
```

### Rebuild after code change

```bash
docker build -t plugger-ai-security-report:latest .
plugger restart ai-security-report
```

### All plugins

```bash
for d in pce-health-monitor traffic-reporter policy-diff pce-posture-report \
         pce-events ai-assisted-rules stale-workloads palo-alto-dag-sync \
         ad-label-sync rule-scheduler ai-security-report remedy-cmdb-sync \
         policy-resolver ztna-sync infoblox-ipam-sync; do
  echo "Building $d..."
  docker build -t "plugger-$d:latest" "$d/"
done
```

## CI Pipeline

### `.github/workflows/build.yml`

Triggers on push to `main` and tags matching `v*`.

#### Docker Job (15 plugins in parallel)

```yaml
docker:
  strategy:
    fail-fast: false
    matrix:
      plugin:
        - pce-health-monitor
        - traffic-reporter
        - policy-diff
        # ... all 15
```

Each plugin:
1. Sets up Docker Buildx + QEMU (for multi-arch)
2. Logs into GHCR with `GITHUB_TOKEN`
3. Generates image tags via `docker/metadata-action`:
   - `latest` on push to main
   - `0.3.0` and `0.3` on tag `v0.3.0`
   - Short SHA on every build
4. Builds `linux/amd64` + `linux/arm64` via `docker/build-push-action`
5. Pushes to `ghcr.io/alexgoller/plugger-{name}`
6. Uses GHA cache for faster rebuilds

#### CLI Job (4 platforms)

Builds the Go CLI binary for:
- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`

Version injected via `-ldflags`. Binaries uploaded as GitHub Actions artifacts.

#### Release Job (tags only)

On `v*` tags, after docker + cli jobs pass:
1. Downloads all CLI artifacts
2. Creates a GitHub Release with auto-generated release notes
3. Attaches CLI binaries (`plugger-linux-amd64`, `plugger-darwin-arm64`, etc.)

### `.github/workflows/pages.yml`

Triggers on push to `main` when `docs/portal/**` changes. Deploys the portal website to GitHub Pages.

## Image Naming Convention

| Image | Description |
|-------|-------------|
| `ghcr.io/alexgoller/plugger-pce-health-monitor:latest` | Latest build from main |
| `ghcr.io/alexgoller/plugger-pce-health-monitor:0.2.0` | Tagged release |
| `ghcr.io/alexgoller/plugger-pce-health-monitor:0.2` | Major.minor (auto-updated) |
| `ghcr.io/alexgoller/plugger-pce-health-monitor:abc1234` | Specific commit SHA |

## Image Tagging Strategy

```
Push to main:
  → latest
  → sha-abc1234

Tag v0.3.0:
  → latest
  → 0.3.0
  → 0.3
  → sha-abc1234
```

## Plugin Docker Image Structure

Every plugin image follows the same layout:

```
/
├── app/
│   ├── main.py              # Plugin entry point
│   ├── ai_advisor.py         # (optional) Additional modules
│   └── ...
├── .plugger/
│   └── metadata.yaml         # Plugin metadata (ports, config, info, version)
├── data/                      # Persistent volume mount point
└── (non-root user: plugin or node, uid 1000)
```

### Base images

| Language | Base Image | Size |
|----------|-----------|------|
| Python | `python:3.12-slim` | ~150MB |
| Node.js | `node:20-slim` | ~200MB |
| Go | Built from source, `scratch` possible | ~15MB |

### Standard Dockerfile pattern (Python)

```dockerfile
FROM python:3.12-slim

# Dependencies first (layer caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Non-root user
RUN useradd -m -u 1000 plugin

# Plugin code
COPY main.py /app/main.py
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

# Version injection
ARG VERSION=0.1.0
RUN sed -i "s/^  version: .*/  version: \"${VERSION}\"/" /.plugger/metadata.yaml || true

# Persistent data directory
RUN mkdir -p /data && chown plugin:plugin /data

USER plugin
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["python3", "main.py"]
```

## Release Process

### 1. Bump versions

Edit `plugin.yaml` and `registry.json` for changed plugins:

```bash
# Example: bump policy-resolver from 0.1.0 to 0.3.0
vim policy-resolver/plugin.yaml        # version: 0.3.0
vim docs/portal/registry.json          # "version": "0.3.0"
```

### 2. Commit and push

```bash
git add -A
git commit -m "Bump policy-resolver to 0.3.0"
git push
```

This triggers the CI pipeline which builds and pushes `plugger-policy-resolver:latest`.

### 3. Tag and release

```bash
git tag v0.3.0
git push origin v0.3.0
```

This triggers:
- All 15 plugin images tagged with `0.3.0` and `0.3`
- CLI binaries built for 4 platforms
- GitHub Release created with release notes and binaries

### 4. Users upgrade

```bash
plugger outdated                      # Shows new versions available
plugger upgrade policy-resolver       # Pulls new image, restarts
```

## External Project: illumio-policy-gitops

The policy-gitops and policy-workflow plugins live in a separate repo with their own CI:

**Repo:** https://github.com/alexgoller/illumio-policy-gitops

**Images:**
- `ghcr.io/alexgoller/illumio-policy-gitops:latest` (GitOps plugin)
- `ghcr.io/alexgoller/illumio-policy-workflow:latest` (Workflow plugin)

**CI:** `.github/workflows/build.yml` in that repo builds both images in parallel with the same multi-arch + version injection pattern.

## Troubleshooting

### Image not found on install

```
Error: pull access denied for plugger-my-plugin
```

The image hasn't been pushed to GHCR yet. Build locally first:
```bash
docker build -t plugger-my-plugin:latest my-plugin/
plugger install my-plugin/plugin.yaml
```

### Version mismatch

`plugger status my-plugin` shows `0.1.0` but you expected `0.3.0`:

1. Check the image was built with `--build-arg VERSION=0.3.0`
2. Verify: `docker inspect plugger-my-plugin:latest | grep VERSION`
3. Or check inside: `docker run --rm plugger-my-plugin:latest cat /.plugger/metadata.yaml | grep version`

### Build cache stale

If Docker serves a cached layer with old code:
```bash
docker build --no-cache -t plugger-my-plugin:latest my-plugin/
```

### Multi-arch build locally

Requires Docker Buildx:
```bash
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -t plugger-my-plugin:latest my-plugin/ --push
```
