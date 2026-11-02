#!/usr/bin/env python3
"""Import real AI agent logs into the lab's event schema, then run detect.py on them.

  # Claude Code transcripts (macOS/Linux: ~/.claude/projects/<project>/*.jsonl)
  python3 import_logs.py ~/.claude/projects/*/*.jsonl --out logs_real
  python3 detect.py --events logs_real/events.jsonl --labels none

  # OpenAI / Ollama-style chat logs
  python3 import_logs.py my_agent_logs.jsonl --format openai --internal-domain mycompany.com

Real logs have no ground truth, so detect.py runs in alert-only mode (--labels none).
The output contains whatever was in your logs, including any secrets: keep logs_real*/
out of git (it is in .gitignore).
"""
import argparse
import glob
import os
import sys

from lab.importers import IMPORTERS, Enricher, Writer, detect_format


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+", help="log files or globs")
    p.add_argument("--format", choices=["auto", *IMPORTERS], default="auto")
    p.add_argument("--out", default="logs_real")
    p.add_argument("--internal-domain", action="append", default=[],
                   help="domain treated as internal (repeatable), e.g. mycompany.com")
    p.add_argument("--internal-mcp", action="append", default=[],
                   help="MCP server name treated as internal (repeatable)")
    p.add_argument("--no-split", action="store_true",
                   help="keep a whole transcript as one session instead of one session per user prompt")
    a = p.parse_args()

    files = sorted({f for pat in a.paths for f in (glob.glob(os.path.expanduser(pat)) or [pat])})
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        sys.exit("No input files found.")
    os.makedirs(a.out, exist_ok=True)
    out_path = os.path.join(a.out, "events.jsonl")
    enricher = Enricher(a.internal_domain, a.internal_mcp)
    with open(out_path, "w", encoding="utf-8") as out:
        w = Writer(out, enricher, split_turns=not a.no_split)
        for f in files:
            fmt = detect_format(f) if a.format == "auto" else a.format
            before = w.sessions
            try:
                IMPORTERS[fmt](f, w)
            except Exception as e:  # keep going on one bad file
                print(f"  skipped {f}: {e}", file=sys.stderr)
                continue
            print(f"{fmt:12} {w.sessions - before:4} sessions  {f}")
    print(f"\n{w.sessions} sessions -> {out_path}")
    print(f"Next: python3 detect.py --events {out_path} --labels none --alerts {os.path.join(a.out, 'alerts.jsonl')}")


if __name__ == "__main__":
    main()
