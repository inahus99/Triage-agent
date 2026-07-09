"""Command-line entry point: run the full triage pipeline on a real file.

Usage:
    python -m triage_agent.cli path/to/sample.exe
    python -m triage_agent.cli path/to/sample.exe --db reports.db
    python -m triage_agent.cli path/to/sample.exe --no-db
    python -m triage_agent.cli path/to/sample.exe --dynamic
"""

import argparse
import os
import sys
from pathlib import Path

from .judgment import render_verdict
from .pipeline import triage
from .reporting import init_db
from .tools.dynamic_analysis import run_dynamic_analysis


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the malware triage pipeline on a file.")
    parser.add_argument("file", type=Path, help="Path to the sample file to analyze")
    parser.add_argument("--db", type=Path, default=Path("triage.db"), help="SQLite report DB path")
    parser.add_argument("--no-db", action="store_true", help="Skip persisting a report")
    parser.add_argument(
        "--dynamic",
        action="store_true",
        help="Also detonate the file in a cloud sandbox (Hybrid Analysis). "
        "Requires HYBRID_ANALYSIS_API_KEY and can take several minutes.",
    )
    args = parser.parse_args(argv)

    if not args.file.exists():
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 1

    _load_dotenv()
    if "OPENAI_API_KEY" not in os.environ:
        print("error: OPENAI_API_KEY not set (in environment or .env)", file=sys.stderr)
        return 1
    if args.dynamic and "HYBRID_ANALYSIS_API_KEY" not in os.environ:
        print("error: HYBRID_ANALYSIS_API_KEY not set (in environment or .env)", file=sys.stderr)
        return 1

    data = args.file.read_bytes()
    conn = None if args.no_db else init_db(args.db)
    dynamic_analysis = (lambda d: run_dynamic_analysis(d, filename=args.file.name)) if args.dynamic else None

    if args.dynamic:
        print("Submitting to sandbox, this can take a few minutes...")

    verdict = triage(data, judge=render_verdict, conn=conn, dynamic_analysis=dynamic_analysis)
    _print_verdict(verdict)

    if conn is not None:
        print(f"\nReport saved to {args.db}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
