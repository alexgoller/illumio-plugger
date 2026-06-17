"""Command-line entry point for the vulnerability-map import prototype.

File imports (parse a saved scanner export):
    python -m illumio_vuln_import.cli \
        --scanner nessus --input scan.nessus \
        --pce-host pce.example.com --org-id 1 \
        --api-key-id 'api_xxx' --api-key-secret 'secret' --authoritative

API imports (pull live from the scanner, creds via env vars; see README):
    QAP_HOST=... QAP_USER_NAME=... QAP_PASSWORD=... \
    python -m illumio_vuln_import.cli --scanner qualys-api \
        --pce-host pce.example.com --org-id 1 \
        --api-key-id 'api_xxx' --api-key-secret 'secret'

Dry run (build payloads, print them, never touch the PCE):
    python -m illumio_vuln_import.cli --scanner tenable-sc --input sc.csv --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import API_PROCESSORS, FILE_PROCESSORS, PROCESSORS
from .pce_client import PCEClient


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="illumio-vuln-import", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scanner", required=True, choices=sorted(PROCESSORS),
                   help="Report source. File: %s | API: %s"
                        % (", ".join(sorted(FILE_PROCESSORS)), ", ".join(sorted(API_PROCESSORS))))
    p.add_argument("--input", help="Path to the scanner report file (file scanners only)")
    p.add_argument("--authoritative", action="store_true",
                   help="Mark report authoritative (PCE marks unlisted prior detections fixed)")
    p.add_argument("--pce-version", default=os.environ.get("ILO_PCE_VERSION", "24.2.0"),
                   help="Target PCE version (>=20.2 enables incremental upload + state)")
    p.add_argument("--mitigated", action="store_true",
                   help="(tenable-sc file) input is a mitigated/fixed export")

    g = p.add_argument_group("PCE connection")
    g.add_argument("--pce-host", default=os.environ.get("ILO_SERVER"))
    g.add_argument("--pce-port", type=int, default=int(os.environ.get("ILO_PORT", "443")))
    g.add_argument("--org-id", type=int, default=int(os.environ.get("ILO_ORG_ID", "1")))
    g.add_argument("--api-key-id", default=os.environ.get("ILO_API_KEY_ID"))
    g.add_argument("--api-key-secret", default=os.environ.get("ILO_API_KEY_SECRET"))
    g.add_argument("--no-verify", action="store_true", help="Disable PCE TLS verification")

    s = p.add_argument_group("scanner API options (api scanners only)")
    s.add_argument("--scanner-host", help="Override scanner host (else from env)")
    s.add_argument("--scanner-page-size", type=int, default=1000)
    s.add_argument("--scanner-since", type=int,
                   help="Incremental window start as epoch seconds (pull only changes since)")
    s.add_argument("--scanner-severities",
                   help="Comma-separated severities to fetch (qualys 1-5, tenable.sc 1-4)")
    s.add_argument("--scanner-no-verify", action="store_true",
                   help="Disable scanner TLS verification")
    s.add_argument("--tio-on-prem", action="store_true",
                   help="(tenable-io-api) target an on-prem host instead of cloud.tenable.com")

    p.add_argument("--dry-run", action="store_true",
                   help="Build payloads, print them, but do not call the PCE")
    p.add_argument("--debug", action="store_true")
    return p


def _build_processor(args):
    cls = PROCESSORS[args.scanner]
    common = dict(xorg_id=args.org_id, debug=args.debug, pce_version=args.pce_version)

    if args.scanner in FILE_PROCESSORS:
        if not args.input:
            raise SystemExit(f"error: --input is required for file scanner '{args.scanner}'")
        kwargs = dict(common, input_file=args.input)
        if args.scanner == "tenable-sc":
            kwargs["mitigated"] = args.mitigated
        return cls(**kwargs)

    # API scanners — creds come from env vars (QAP_*/TSC_*/TIO_*) or prompt
    api_kwargs = dict(common)
    if args.scanner_host:
        api_kwargs["host"] = args.scanner_host
    api_kwargs["page_size"] = args.scanner_page_size
    api_kwargs["verify_cert"] = not args.scanner_no_verify
    if args.scanner_since is not None:
        api_kwargs["since"] = args.scanner_since
    if args.scanner_severities:
        api_kwargs["severities"] = args.scanner_severities
    if args.scanner == "tenable-io-api":
        api_kwargs.pop("severities", None)  # IO export filters severity internally
        api_kwargs["on_premise"] = args.tio_on_prem
    return cls(**api_kwargs)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    processor = _build_processor(args)
    if args.authoritative:
        processor.set_authoritative()

    if args.dry_run:
        _dump_dry_run(processor)
        return 0

    missing = [n for n, v in (
        ("--pce-host", args.pce_host),
        ("--api-key-id", args.api_key_id),
        ("--api-key-secret", args.api_key_secret),
    ) if not v]
    if missing:
        print(f"error: missing required PCE arguments: {', '.join(missing)}", file=sys.stderr)
        return 2

    pce = PCEClient(
        host=args.pce_host,
        org_id=args.org_id,
        api_key_id=args.api_key_id,
        api_key_secret=args.api_key_secret,
        port=args.pce_port,
        verify=not args.no_verify,
    )
    processor.run_import(pce)
    return 0


def _dump_dry_run(processor) -> None:
    print("=== vulnerability definitions ===")
    vulns = [{"reference_id": ref, **v} for ref, v in processor.vulnerabilities.items()]
    print(json.dumps(vulns[:20], indent=2))
    print(f"... {len(vulns)} vulnerability definitions total")

    print("\n=== detected vulnerabilities (pre workload-association) ===")
    dvs = list(processor._detected_vulnerabilities_map.values())
    print(json.dumps(dvs[:20], indent=2))
    print(f"... {len(dvs)} detected vulnerabilities total")

    print("\n=== report metadata ===")
    meta = {k: v for k, v in processor.report.items() if k != "scanned_ips"}
    meta["scanned_ips_count"] = len(processor.report.get("scanned_ips", []))
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
