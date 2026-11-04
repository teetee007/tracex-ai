"""Run every scenario in both modes and write docs/TEST_RESULTS.md.

Run:  python scripts/run_evaluation.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tracex.lab import run, to_markdown  # noqa: E402


def main():
    df = run(ROOT / "data")
    out = ROOT / "docs" / "TEST_RESULTS.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(to_markdown(df), encoding="utf-8")
    cols = ["scenario", "mode", "incidents", "fragmentation", "missed", "false positives", "recall", "precision"]
    print(df[cols].to_string(index=False))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
