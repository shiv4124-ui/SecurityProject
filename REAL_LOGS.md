# Running the rules on real agent logs

The lab generates synthetic sessions, but the same correlation rules can run on logs
from a real AI agent. `import_logs.py` converts real logs into the lab's
`events.jsonl` schema; `detect.py` then runs on them in alert-only mode (no ground
truth, so no detection-rate scoring).

```bash
# Claude Code transcripts (one per project session)
#   macOS/Linux: ~/.claude/projects/<project>/<session>.jsonl
python3 import_logs.py ~/.claude/projects/*/*.jsonl --out logs_real
python3 detect.py --events logs_real/events.jsonl --labels none

# OpenAI / Ollama-style chat logs ({"messages": [...], "tools": [...]} per session)
python3 import_logs.py my_logs.jsonl --format openai --internal-domain mycompany.com
python3 detect.py --events logs_real/events.jsonl --labels none
```

Try it now on the bundled samples (synthetic, safe to share):

```bash
python3 import_logs.py samples/claude_code_sample.jsonl --out logs_real
python3 detect.py --events logs_real/events.jsonl --labels none
# -> the exfil session alerts (R2 + R6); the benign README session stays quiet

python3 import_logs.py samples/openai_sample.jsonl --internal-domain acme-internal.example
python3 detect.py --events logs_real/events.jsonl --labels none
# -> the indirect-injection session alerts (R2 + R5 + R6, secret caught base64-encoded)
```

## Supported formats

| `--format` | Input |
|---|---|
| `claude-code` | Claude Code session transcripts (JSONL, `tool_use` / `tool_result` blocks) |
| `openai` | `{"messages": [...], "tools": [...]}` per session — OpenAI chat logs, Ollama `/api/chat` logs, most agent frameworks, and `{"request": ..., "response": ...}` gateway logs. `.json` object, `.json` list, or `.jsonl`. |
| `auto` (default) | Sniffs the file and picks one |

By default each user prompt starts a new lab "session" (`--no-split` keeps a whole
transcript as one). Use `--internal-domain` / `--internal-mcp` (repeatable) to mark
destinations that should not count as egress.

## The hard part: enrichment

Real logs do not carry the signals the lab generates natively — whether a tool reads
or writes, whether a result is untrusted, whether it is secret, and what left the
org. `lab/importers.py` (`Enricher`) infers them:

| Lab signal | How it is inferred from a real log |
|---|---|
| `kind` read/write | Tool name (`Read`/`Edit`/…), and for `Bash`, whether the command writes or makes a network call |
| `trust` untrusted | MCP tools, web fetch/search, and `Bash` commands that touch the network |
| `sensitivity` secret | Secret file paths (`.env`, `id_rsa`, `credentials`…) and secret-shaped content (keys, tokens, `password=`) |
| `egress` | `WebFetch`/`fetch_url` URLs, `Bash` network commands (curl/scp/ssh/`git push`), MCP calls, and send/post-style tools, minus internal destinations |

These are heuristics. Tune the pattern sets at the top of `lab/importers.py` for your
environment. Two consequences worth stating in a write-up:

- **False negatives:** a custom exfel path the patterns don't know about is invisible
  to the rules. The importer can only surface what it can label.
- **R6 needs the secret content.** When a secret is identified by file path, the
  importer stores the whole result as `secret_material`; when identified by content,
  it stores just the matched tokens. R6 matches egress against that.

## What this session's own transcript showed

Running the importer on a real Claude Code transcript of this very project (13
prompts) produced **zero alerts** — correct, it is benign work — but `R5` (injection
markers) fired once, below threshold. The cause: the conversation is *about* prompt
injection, so results contained phrases like "ignore previous instructions". This is
the expected weakness of a keyword marker rule, and the reason R5 is weighted 1 and
never alerts alone. Security-research and SOC-analyst traffic will trip marker rules
constantly; lineage and egress rules (R2/R6) are what actually hold up.

## Privacy

Imported logs can contain real secrets and private content. `import_logs.py` writes
to `logs_real/` by default, which is git-ignored. Do not commit it.
