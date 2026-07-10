"""Command-line entry point: run the full triage pipeline on a real file.

Usage:
    python -m triage_agent.cli path/to/sample.exe
    python -m triage_agent.cli path/to/sample.exe --db reports.db
    python -m triage_agent.cli path/to/sample.exe --no-db
    python -m triage_agent.cli path/to/sample.exe --dynamic
"""

import argparse
import json
import os
import sys
from pathlib import Path

from .judgment import render_verdict
from .pipeline import triage
from .reporting import init_db
from .tools.dynamic_analysis import run_dynamic_analysis
from .tools.virustotal import lookup_hash


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env loader so OPENAI_API_KEY doesn't have to be
    exported manually every session. Does not override a value
    already set in the real environment."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _print_verdict(verdict) -> None:
    print(f"Severity:           {verdict.severity}")
    print(f"Confidence:         {verdict.confidence}")
    print(f"Needs human review: {verdict.needs_human_review}")
    print(f"Reasoning:          {verdict.reasoning_summary}")
    if verdict.injection_findings:
        print("\nInjection findings:")
        for f in verdict.injection_findings:
            print(f"  - [{f.pattern}] ({f.source}): {f.excerpt!r}")
    else:
        print("\nInjection findings: none")


def _triage_path(path: Path, conn, dynamic_analysis, enrich):
    data = path.read_bytes()
    return triage(data, judge=render_verdict, conn=conn,
                  dynamic_analysis=dynamic_analysis, enrich=enrich)


def _run_batch(directory: Path, conn, dynamic_analysis, enrich, as_json=False) -> int:
    files = sorted(p for p in directory.iterdir() if p.is_file())
    if not files:
        print(f"error: no files in directory: {directory}", file=sys.stderr)
        return 1

    if as_json:
        results = []
        for path in files:
            verdict = _triage_path(path, conn, dynamic_analysis, enrich)
            results.append({"file": path.name, **verdict.model_dump(mode="json")})
        print(json.dumps(results, indent=2))
        return 0

    print(f"Triaging {len(files)} file(s) in {directory}\n")
    header = f"{'FILE':<32}{'SEVERITY':<12}{'REVIEW':<8}FINDINGS"
    print(header)
    print("-" * len(header))
    for path in files:
        verdict = _triage_path(path, conn, dynamic_analysis, enrich)
        review = "YES" if verdict.needs_human_review else ""
        print(f"{path.name[:31]:<32}{verdict.severity:<12}{review:<8}{len(verdict.injection_findings)}")

    if conn is not None:
        print("\nReports saved.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the malware triage pipeline on a file.")
    parser.add_argument("file", type=Path, nargs="?", help="Path to the sample file to analyze")
    parser.add_argument("--dir", type=Path, help="Triage every file in this directory (batch mode)")
    parser.add_argument("--db", type=Path, default=Path("triage.db"), help="SQLite report DB path")
    parser.add_argument("--no-db", action="store_true", help="Skip persisting a report")
    parser.add_argument(
        "--dynamic",
        action="store_true",
        help="Also detonate the file in a cloud sandbox (Hybrid Analysis). "
        "Requires HYBRID_ANALYSIS_API_KEY and can take several minutes.",
    )
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Enrich with a VirusTotal hash lookup (read-only, free tier). "
        "Requires VIRUSTOTAL_API_KEY.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text")
    args = parser.parse_args(argv)

    if not args.file and not args.dir:
        print("error: provide a file or --dir", file=sys.stderr)
        return 1
    if args.file and args.dir:
        print("error: provide either a file or --dir, not both", file=sys.stderr)
        return 1
    if args.file and not args.file.exists():
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 1
    if args.dir and not args.dir.is_dir():
        print(f"error: not a directory: {args.dir}", file=sys.stderr)
        return 1

    _load_dotenv()
    if "OPENAI_API_KEY" not in os.environ:
        print("error: OPENAI_API_KEY not set (in environment or .env)", file=sys.stderr)
        return 1
    if args.dynamic and "HYBRID_ANALYSIS_API_KEY" not in os.environ:
        print("error: HYBRID_ANALYSIS_API_KEY not set (in environment or .env)", file=sys.stderr)
        return 1
    if args.vt and "VIRUSTOTAL_API_KEY" not in os.environ:
        print("error: VIRUSTOTAL_API_KEY not set (in environment or .env)", file=sys.stderr)
        return 1

    conn = None if args.no_db else init_db(args.db)
    dynamic_analysis = (lambda d: run_dynamic_analysis(d)) if args.dynamic else None
    enrich = lookup_hash if args.vt else None

    if args.dynamic and not args.json:
        print("Dynamic sandbox analysis enabled; each file can take a few minutes...\n")

    if args.dir:
        return _run_batch(args.dir, conn, dynamic_analysis, enrich, as_json=args.json)

    verdict = _triage_path(args.file, conn, dynamic_analysis, enrich)
    if args.json:
        print(json.dumps({"file": args.file.name, **verdict.model_dump(mode="json")}, indent=2))
    else:
        _print_verdict(verdict)
        if conn is not None:
            print(f"\nReport saved to {args.db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
