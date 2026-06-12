#!/usr/bin/env python3
"""
Validate registry.json and CI build matrix consistency.

Checks:
  1. Every plugin with a plugin.yaml has a registry.json entry
  2. Every registry entry has a valid image name
  3. Registry image names match the CI build matrix output
  4. Every in-repo plugin is in the CI build matrix
  5. Registry entry fields are complete (name, version, image, description, mode)
  6. External plugins (policy-gitops, policy-workflow) use correct image prefix
"""

import json
import os
import re
import sys
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SKIP_DIRS = {
    "docs", "internal", "cmd", "bin", "vendor", ".git", ".github", ".claude",
    "plugin-templates", "node_modules", "__pycache__",
}

# Plugins that live in an external repo and are NOT built by this CI
EXTERNAL_PLUGINS = {"policy-gitops", "policy-workflow"}

# External plugins use a different image prefix
EXTERNAL_IMAGE_PREFIX = "ghcr.io/alexgoller/illumio-"
INTERNAL_IMAGE_PREFIX = "ghcr.io/alexgoller/plugger-"


def find_plugins():
    plugins = []
    for entry in sorted(os.listdir(REPO_ROOT)):
        if entry in SKIP_DIRS or entry.startswith("."):
            continue
        plugin_dir = os.path.join(REPO_ROOT, entry)
        if os.path.isdir(plugin_dir) and os.path.exists(os.path.join(plugin_dir, "plugin.yaml")):
            plugins.append(entry)
    return plugins


def load_registry():
    path = os.path.join(REPO_ROOT, "docs", "portal", "registry.json")
    with open(path) as f:
        return json.load(f)


def load_ci_matrix():
    path = os.path.join(REPO_ROOT, ".github", "workflows", "build.yml")
    with open(path) as f:
        content = f.read()

    # Extract plugin names from the matrix
    plugins = []
    in_matrix = False
    for line in content.split("\n"):
        stripped = line.strip()
        if "plugin:" in stripped or "matrix:" in stripped:
            in_matrix = True
            continue
        if in_matrix and stripped.startswith("- ") and not any(k in stripped for k in ["name:", "runs-on:", "goos:", "goarch:", "component:", "image:", "context:"]):
            plugin_name = stripped.lstrip("- ").strip()
            if plugin_name and not plugin_name.startswith("#"):
                plugins.append(plugin_name)
        elif in_matrix and not stripped.startswith("-") and not stripped.startswith("#") and stripped and ":" not in stripped:
            pass
        elif in_matrix and stripped and not stripped.startswith("-") and not stripped.startswith("#"):
            if "steps:" in stripped or "name:" in stripped:
                in_matrix = False

    return plugins


def main():
    plugins = find_plugins()
    registry = load_registry()
    ci_plugins = load_ci_matrix()

    registry_by_name = {p["name"]: p for p in registry.get("plugins", [])}
    ci_set = set(ci_plugins)

    errors = 0
    warnings = 0

    print(f"Found {len(plugins)} plugins, {len(registry_by_name)} registry entries, {len(ci_set)} CI matrix entries\n")

    # Check 1: Every plugin has a registry entry
    for plugin in plugins:
        if plugin not in registry_by_name:
            print(f"❌ {plugin}: missing from registry.json")
            errors += 1

    # Check 2: Every registry entry points to a real plugin
    for name in registry_by_name:
        if name not in plugins:
            print(f"⚠️  {name}: in registry but no plugin directory found")
            warnings += 1

    # Check 3: Registry entries have correct image names
    for name, entry in registry_by_name.items():
        image = entry.get("image", "")
        if name in EXTERNAL_PLUGINS:
            expected_prefix = EXTERNAL_IMAGE_PREFIX
            expected_image = f"{expected_prefix}{name}:latest"
        else:
            expected_prefix = INTERNAL_IMAGE_PREFIX
            expected_image = f"{expected_prefix}{name}:latest"

        if not image:
            print(f"❌ {name}: missing image field in registry")
            errors += 1
        elif image != expected_image:
            print(f"❌ {name}: wrong image name")
            print(f"     got:      {image}")
            print(f"     expected: {expected_image}")
            errors += 1

    # Check 4: Every in-repo plugin is in CI build matrix
    for plugin in plugins:
        if plugin in EXTERNAL_PLUGINS:
            continue
        if plugin not in ci_set:
            print(f"❌ {plugin}: missing from CI build matrix (.github/workflows/build.yml)")
            errors += 1

    # Check 5: CI matrix doesn't have stale entries
    for ci_plugin in ci_set:
        if ci_plugin not in plugins:
            print(f"⚠️  {ci_plugin}: in CI matrix but no plugin directory")
            warnings += 1

    # Check 6: Registry entry completeness
    required_fields = ["name", "version", "image", "description", "mode", "has_ui", "language", "tags", "homepage", "maturity"]
    for name, entry in registry_by_name.items():
        missing = [f for f in required_fields if f not in entry]
        if missing:
            print(f"⚠️  {name}: registry entry missing fields: {', '.join(missing)}")
            warnings += 1

    # Check 7: Maturity values are valid
    valid_maturity = {"example", "preview", "prototype", "production"}
    for name, entry in registry_by_name.items():
        m = entry.get("maturity", "")
        if m and m not in valid_maturity:
            print(f"❌ {name}: invalid maturity '{m}' (must be one of {valid_maturity})")
            errors += 1

    # Check 8: Registry version matches plugin.yaml version
    for plugin in plugins:
        plugin_yaml_path = os.path.join(REPO_ROOT, plugin, "plugin.yaml")
        try:
            with open(plugin_yaml_path) as f:
                pdata = yaml.safe_load(f)
            plugin_version = str(pdata.get("version", ""))
            reg_entry = registry_by_name.get(plugin, {})
            reg_version = str(reg_entry.get("version", ""))
            if plugin_version and reg_version and plugin_version != reg_version:
                print(f"⚠️  {plugin}: version mismatch — plugin.yaml={plugin_version}, registry={reg_version}")
                warnings += 1
        except Exception:
            pass

    print(f"\n{'='*60}")
    print(f"Plugins: {len(plugins)}  |  Errors: {errors}  |  Warnings: {warnings}")

    if errors > 0:
        print(f"\n❌ FAILED: {errors} error(s)")
        sys.exit(1)
    elif warnings > 0:
        print(f"\n⚠️  PASSED with {warnings} warning(s)")
    else:
        print(f"\n✅ ALL PASSED")


if __name__ == "__main__":
    main()
