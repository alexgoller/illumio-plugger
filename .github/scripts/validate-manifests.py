#!/usr/bin/env python3
"""
Validate all plugin manifests (plugin.yaml + metadata.yaml + Dockerfile).

Checks:
  1. plugin.yaml exists, is valid YAML, has required fields
  2. .plugger/metadata.yaml exists, is valid YAML, has required fields
  3. Dockerfile exists and includes both metadata.yaml and plugin.yaml
  4. Consistency between plugin.yaml and metadata.yaml
  5. Config vars in metadata.yaml have required fields
"""

import os
import re
import sys
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Directories that are NOT plugins
SKIP_DIRS = {
    "docs", "internal", "cmd", "bin", "vendor", ".git", ".github", ".claude",
    "plugin-templates", "node_modules", "__pycache__",
}

REQUIRED_PLUGIN_YAML_FIELDS = ["apiVersion", "name", "version", "image", "schedule"]
REQUIRED_METADATA_FIELDS = ["plugger"]
REQUIRED_INFO_FIELDS = ["title", "description"]
VALID_MODES = {"daemon", "cron", "event"}
VALID_CONFIG_TYPES = {"string", "int", "bool", "secret"}


def find_plugins():
    """Find all plugin directories (contain plugin.yaml)."""
    plugins = []
    for entry in sorted(os.listdir(REPO_ROOT)):
        if entry in SKIP_DIRS or entry.startswith("."):
            continue
        plugin_dir = os.path.join(REPO_ROOT, entry)
        if not os.path.isdir(plugin_dir):
            continue
        if os.path.exists(os.path.join(plugin_dir, "plugin.yaml")):
            plugins.append(entry)
    return plugins


def validate_yaml_file(filepath):
    """Parse YAML file, return (data, error)."""
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
        if data is None:
            return None, "File is empty"
        if not isinstance(data, dict):
            return None, f"Expected dict, got {type(data).__name__}"
        return data, None
    except yaml.YAMLError as e:
        return None, f"YAML parse error: {e}"
    except Exception as e:
        return None, f"Read error: {e}"


def validate_plugin_yaml(plugin_name, data):
    """Validate plugin.yaml contents."""
    errors = []

    for field in REQUIRED_PLUGIN_YAML_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    if "name" in data and data["name"] != plugin_name:
        # Allow mismatches for pointer plugins (policy-gitops, policy-workflow)
        pass

    if "version" in data:
        version = str(data["version"])
        if not re.match(r"^\d+\.\d+\.\d+", version):
            errors.append(f"Version '{version}' is not semver (expected X.Y.Z)")

    if "schedule" in data:
        schedule = data["schedule"]
        if isinstance(schedule, dict):
            mode = schedule.get("mode", "")
            if mode and mode not in VALID_MODES:
                errors.append(f"Invalid schedule mode '{mode}' (expected: {VALID_MODES})")
            if mode == "cron" and "cron" not in schedule:
                errors.append("Cron mode requires 'cron' field with schedule expression")

    if "image" in data:
        image = str(data["image"])
        if not image:
            errors.append("Image field is empty")

    return errors


def validate_metadata_yaml(plugin_name, data):
    """Validate .plugger/metadata.yaml contents."""
    errors = []

    if "plugger" not in data:
        errors.append("Missing required field: plugger (version identifier)")

    # Validate ports
    ports = data.get("ports", [])
    if isinstance(ports, list):
        for i, port in enumerate(ports):
            if not isinstance(port, dict):
                errors.append(f"ports[{i}]: expected dict")
                continue
            if "port" not in port:
                errors.append(f"ports[{i}]: missing 'port' field")
            if "protocol" not in port:
                errors.append(f"ports[{i}]: missing 'protocol' field")

    # Validate config entries
    config = data.get("config", [])
    if isinstance(config, list):
        seen_names = set()
        for i, cfg in enumerate(config):
            if not isinstance(cfg, dict):
                errors.append(f"config[{i}]: expected dict")
                continue
            name = cfg.get("name", "")
            if not name:
                errors.append(f"config[{i}]: missing 'name' field")
            elif name in seen_names:
                errors.append(f"config[{i}]: duplicate name '{name}'")
            else:
                seen_names.add(name)

            if "description" not in cfg:
                errors.append(f"config[{i}] ({name}): missing 'description'")

            cfg_type = cfg.get("type", "string")
            if cfg_type not in VALID_CONFIG_TYPES:
                errors.append(f"config[{i}] ({name}): invalid type '{cfg_type}' (expected: {VALID_CONFIG_TYPES})")

    # Validate info section
    info = data.get("info", {})
    if isinstance(info, dict):
        for field in REQUIRED_INFO_FIELDS:
            if field not in info:
                errors.append(f"info: missing '{field}' field")
        if "version" not in info:
            errors.append("info: missing 'version' field (needed for registry install)")
    else:
        errors.append("info: expected dict")

    return errors


def validate_dockerfile(plugin_name, plugin_dir):
    """Validate Dockerfile includes required COPY instructions."""
    errors = []
    dockerfile_path = os.path.join(plugin_dir, "Dockerfile")

    if not os.path.exists(dockerfile_path):
        errors.append("Dockerfile not found")
        return errors

    with open(dockerfile_path) as f:
        content = f.read()

    if "metadata.yaml" not in content:
        errors.append("Dockerfile missing: COPY .plugger/metadata.yaml /.plugger/metadata.yaml")

    if "plugin.yaml" not in content:
        errors.append("Dockerfile missing: COPY plugin.yaml /.plugger/plugin.yaml")

    if "ENTRYPOINT" not in content and "CMD" not in content:
        errors.append("Dockerfile missing: ENTRYPOINT or CMD")

    return errors


def validate_consistency(plugin_name, plugin_data, metadata_data):
    """Check consistency between plugin.yaml and metadata.yaml."""
    errors = []

    # Check that plugin.yaml env vars are covered in metadata config
    plugin_envs = set()
    for env in plugin_data.get("env", []):
        if isinstance(env, dict) and "name" in env:
            plugin_envs.add(env["name"])

    metadata_configs = set()
    for cfg in metadata_data.get("config", []):
        if isinstance(cfg, dict) and "name" in cfg:
            metadata_configs.add(cfg["name"])

    # PCE vars are injected by plugger, not in metadata
    pce_vars = {"PCE_HOST", "PCE_PORT", "PCE_ORG_ID", "PCE_API_KEY", "PCE_API_SECRET"}
    plugin_envs -= pce_vars

    missing_in_metadata = plugin_envs - metadata_configs
    if missing_in_metadata:
        for var in sorted(missing_in_metadata):
            # Only warn for non-standard vars
            if not var.startswith("PCE_"):
                errors.append(f"Consistency: '{var}' in plugin.yaml env but not in metadata.yaml config")

    return errors


def main():
    plugins = find_plugins()
    print(f"Found {len(plugins)} plugins to validate\n")

    total_errors = 0
    total_warnings = 0

    for plugin_name in plugins:
        plugin_dir = os.path.join(REPO_ROOT, plugin_name)
        plugin_yaml_path = os.path.join(plugin_dir, "plugin.yaml")
        metadata_path = os.path.join(plugin_dir, ".plugger", "metadata.yaml")

        errors = []
        warnings = []

        # Validate plugin.yaml
        plugin_data, parse_err = validate_yaml_file(plugin_yaml_path)
        if parse_err:
            errors.append(f"plugin.yaml: {parse_err}")
        elif plugin_data:
            errors.extend([f"plugin.yaml: {e}" for e in validate_plugin_yaml(plugin_name, plugin_data)])

        # Validate metadata.yaml
        if os.path.exists(metadata_path):
            metadata_data, parse_err = validate_yaml_file(metadata_path)
            if parse_err:
                errors.append(f"metadata.yaml: {parse_err}")
            elif metadata_data:
                errors.extend([f"metadata.yaml: {e}" for e in validate_metadata_yaml(plugin_name, metadata_data)])
        else:
            errors.append("metadata.yaml: file not found at .plugger/metadata.yaml")
            metadata_data = None

        # Validate Dockerfile
        errors.extend([f"Dockerfile: {e}" for e in validate_dockerfile(plugin_name, plugin_dir)])

        # Consistency checks
        if plugin_data and metadata_data:
            warnings.extend(validate_consistency(plugin_name, plugin_data, metadata_data))

        # Report
        if errors or warnings:
            status = "FAIL" if errors else "WARN"
            print(f"{'❌' if errors else '⚠️'}  {plugin_name} [{status}]")
            for e in errors:
                print(f"     ERROR: {e}")
                total_errors += 1
            for w in warnings:
                print(f"     WARN:  {w}")
                total_warnings += 1
        else:
            print(f"✅  {plugin_name}")

    print(f"\n{'='*60}")
    print(f"Plugins: {len(plugins)}  |  Errors: {total_errors}  |  Warnings: {total_warnings}")

    if total_errors > 0:
        print(f"\n❌ FAILED: {total_errors} error(s) found")
        sys.exit(1)
    elif total_warnings > 0:
        print(f"\n⚠️  PASSED with {total_warnings} warning(s)")
    else:
        print(f"\n✅ ALL PASSED")


if __name__ == "__main__":
    main()
