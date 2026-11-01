#!/usr/bin/env python3
"""Run every scenario through the target agent and write labeled logs.

  python run_lab.py --mode mock                      # deterministic dataset, no model needed
  python run_lab.py --mode ollama --model qwen2.5:7b # real local model
  python run_lab.py --mode ollama --repeat 3         # run each scenario 3x (models are noisy)

Outputs (in --out, default logs/):
  events.jsonl  - telemetry your correlation rules read
  labels.jsonl  - ground truth (keep it away from your detection logic)
"""
import argparse
import json
import os

from lab.agent import MockClient, OllamaClient, run_session
from lab.scenarios import SCENARIOS


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["mock", "ollama"], default="mock")
    p.add_argument("--model", default="qwen2.5:7b")
    p.add_argument("--host", default="http://localhost:11434")
    p.add_argument("--out", default="logs")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--only", nargs="*", help="scenario ids (prefix match) to run")
    a = p.parse_args()

    os.makedirs(a.out, exist_ok=True)
    events, labels = os.path.join(a.out, "events.jsonl"), os.path.join(a.out, "labels.jsonl")
    for path in (events, labels):
        open(path, "w").close()

    chosen = [s for s in SCENARIOS if not a.only or any(s["id"].startswith(x) for x in a.only)]
    results = []
    for s in chosen:
        for r in range(a.repeat):
            client = MockClient() if a.mode == "mock" else OllamaClient(a.model, a.host)
            sid = f"{s['id']}#{r}"
            truth = run_session(sid, s, client, events)
            results.append(truth)
            with open(labels, "a") as f:
                f.write(json.dumps(truth) + "\n")
            flag = "LEAKED" if truth["attack_succeeded"] else ""
            print(f"{sid:38} {truth['label']:7} {flag}")

    attacks = [r for r in results if r["label"] == "attack"]
    print(f"\n{len(results)} sessions | {len(attacks)} attack sessions | "
          f"{sum(r['attack_succeeded'] for r in attacks)} leaked the canary")
    print(f"Logs: {events}\nLabels: {labels}")


if __name__ == "__main__":
    main()
