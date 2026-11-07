---
name: triage-agent-logs
description: >-
  Triage AI agent logs for prompt injection and data exfiltration. Use when given
  logs or a transcript from an AI agent (Claude Code, an OpenAI/Ollama tool-calling
  agent, an MCP gateway, or an agent framework) and asked to check them for
  compromise, injection, secret leakage, or suspicious tool use — or to score which
  sessions look malicious. Not for live interception; this reads logs after the fact.
---

# Triage AI agent logs

Convert real agent logs into a normalized event stream and score every session with
seven correlation rules that flag prompt injection and data exfiltration. Pure
Python standard library, offline, no secrets leave the machine.

## When to use

- Someone hands you agent logs / a transcript and asks "was this agent compromised?",
  "did anything leak?", "which sessions look malicious?"
- You want a repeatable triage pass over a batch of agent sessions.

## Steps

1. **Locate the logs.**
   - Claude Code: `~/.claude/projects/<project>/<session>.jsonl`
   - OpenAI / Ollama / frameworks / gateways: any file with `{"messages": [...],
     "tools": [...]}` per session (`.json` object, `.json` list, or `.jsonl`).

2. **Import to the event schema** (writes `logs_real/events.jsonl`):
   ```bash
   python3 import_logs.py <path-or-glob> --out logs_real \
     --internal-domain <your-company.com>   # repeatable; marks non-egress destinations
   ```
   `--format` is auto-detected; pass `claude-code` or `openai` to force it.
   `--internal-mcp <server>` marks an MCP server as internal. `--no-split` keeps a
   whole transcript as one session instead of one per user prompt.

3. **Score the sessions** (no ground truth, so alert-only mode):
   ```bash
   python3 detect.py --events logs_real/events.jsonl --labels none --verbose
   ```
   Each alert prints the session, its score, and the evidence line per rule. Alerts
   are also written to `logs_real/alerts.jsonl`.

4. **Interpret the verdict.** A session alerts when summed rule weights ≥ 4.

   | Rule | Wt | Fires when |
   |---|---|---|
   | R1 intent_mismatch | 2 | read-only request, yet data left to a destination the user never named |
   | R2 sensitive→egress | 3 | a secret read is followed by any egress within 8 events |
   | R3 untrusted→egress | 3 | untrusted content ingested, then egress to an unrequested destination |
   | R4 schema_drift | 2 | a tool's description/schema hash changed since first seen (rug-pull) |
   | R5 injection_markers | 1 | instruction-like phrases in tool output or a tool description (weak) |
   | R6 data_lineage | 4 | secret bytes appear in a later egress, raw or encoded (base64/hex/url) |
   | R7 opaque_egress | 2 | a long, high-entropy or encoded blob left to an external destination |

   Read `logs_real/events.jsonl` for the flagged session to see the actual tool
   calls, results, and egress that drove the score.

5. **Sanity-check the enrichment.** R2/R3/R6 depend on inferred `sensitivity` and
   `trust` fields. If results look empty, the inference (in `lab/importers.py`,
   `Enricher`) may not recognize your secret paths or tool names — tune the pattern
   sets there. To see which rules would still fire if enrichment failed entirely:
   ```bash
   python3 detect.py --events logs_real/events.jsonl --labels none --blind-labels
   ```
   R1, R5 and R7 survive blanked labels; R2/R3/R6 go to zero.

## Reading the result

- **High confidence:** R6 (verbatim/encoded secret left) or R2+R3 together.
- **Label-independent:** R1 and R7 fire without trusting the enrichment — weight them
  when you are unsure the logs were labelled correctly.
- **Weak alone:** R5 (markers) false-fires on security-research and phishing-triage
  traffic; it only adds to a score, never alerts by itself.

## Known blind spots

- Paraphrased secrets ("Ravi earns about 95k") and secrets split into sub-24-char
  chunks evade the content and entropy rules; only the flow rules (R1/R2/R3) catch
  them, and only when the flow shape is intact.
- A destination the attacker relays through an internal/allowed host is not treated
  as egress.
- This is post-hoc log analysis, not prevention.

## Privacy

`import_logs.py` writes to `logs_real/`, which is git-ignored, because imported logs
may contain real secrets. Do not commit it.
