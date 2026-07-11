#!/usr/bin/env python3
"""Phase 4f - optional LLM narration of the NeuralGuard weekly digest.

Turns `ngd digest` output into a short plain-English weekly summary. This is
ADVISORY ONLY: it never touches rules, never enforces, and never talks to the
engine - it only reads the digest text you pipe in and writes prose out.

Usage:
    ngd digest ngpolicy.db | python scripts/narrate_digest.py
    ngd digest ngpolicy.db | python scripts/narrate_digest.py --llm

LLM is opt-in and offline-first. With --llm it tries, in order:
  1. A local Ollama server (http://localhost:11434, model $NG_OLLAMA_MODEL or
     "llama3.2") - fully offline, nothing leaves the machine.
  2. The Anthropic API if ANTHROPIC_API_KEY is set (sends the digest text to
     Anthropic - only use on data you're comfortable sending off-device).
Without --llm (or if no backend is reachable) it prints a deterministic,
template-based rollup - no dependencies, no network.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

DISCLAIMER = ("(Advisory summary only - NeuralGuard did not act on any of this. "
              "Demotions bite only in active mode; everything else is shadow.)")

SYSTEM = ("You are a concise security assistant. Given a NeuralGuard weekly "
          "firewall digest, write 4-8 sentences a non-expert can act on: what's "
          "normal, what's new or rare, and anything the ML flagged worth a look. "
          "Be calm and specific, never alarmist. Do not invent data not in the digest.")


def parse_sections(text):
    """Split the digest into {section-title: [lines]} for the fallback summary."""
    sections, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^-{2,}\s*(.*?)\s*-{2,}$", line.strip())
        if m:
            cur = m.group(1)
            sections[cur] = []
        elif cur is not None and line.strip() and line.strip() != "(none)":
            sections[cur].append(line.strip())
    return sections


def template_summary(text):
    """Deterministic prose rollup - no LLM, no network."""
    secs = parse_sections(text)
    out = []
    header = re.search(r"habits=(\d+)\s+apps=(\d+)\s+destinations=(\d+)\s+events=(\d+)", text)
    if header:
        h, a, d, e = header.groups()
        out.append(f"Your baseline holds {h} learned habits across {a} apps and "
                   f"{d} destinations, from {e} recorded events.")
    new = secs.get("new in the last 7 days", [])
    if new:
        out.append(f"{len(new)} new destination(s) appeared this week; newest: "
                   f"{new[0]}.")
    demos = [l for k, v in secs.items() if "ML demotions" in k for l in v]
    if demos:
        out.append(f"The ML tier raised {len(demos)} flag(s): " + "; ".join(demos[:3]) + ".")
    mal = [l for k, v in secs.items() if "suspicious completed flows" in k for l in v]
    if mal:
        out.append("Highest-scored flows: " + "; ".join(mal[:3]) + ".")
    fb = re.search(r"(\d+) verdict\(s\) recorded, (\d+) blocked", text)
    if fb:
        out.append(f"You logged {fb.group(1)} prompt verdict(s), {fb.group(2)} blocked - "
                   "these become retraining labels.")
    if not out:
        out.append("Nothing notable this week - the baseline looks quiet.")
    return " ".join(out)


def via_ollama(text):
    model = os.environ.get("NG_OLLAMA_MODEL", "llama3.2")
    body = json.dumps({
        "model": model, "stream": False,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": text}],
    }).encode()
    req = urllib.request.Request("http://localhost:11434/api/chat", body,
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["message"]["content"].strip()


def via_anthropic(text):
    key = os.environ["ANTHROPIC_API_KEY"]
    body = json.dumps({
        "model": os.environ.get("NG_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
        "max_tokens": 400, "system": SYSTEM,
        "messages": [{"role": "user", "content": text}],
    }).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {
        "Content-Type": "application/json", "x-api-key": key,
        "anthropic-version": "2023-06-01",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        return "".join(b.get("text", "") for b in json.load(r)["content"]).strip()


def main():
    ap = argparse.ArgumentParser(description="Narrate a NeuralGuard digest (advisory).")
    ap.add_argument("--llm", action="store_true",
                    help="try a local Ollama / Anthropic backend before the template fallback")
    args = ap.parse_args()

    digest = sys.stdin.read()
    if not digest.strip():
        sys.exit("no digest on stdin - pipe `ngd digest <db>` into this script.")

    summary, source = None, "template"
    if args.llm:
        for name, fn in (("ollama", via_ollama), ("anthropic", via_anthropic)):
            if name == "anthropic" and "ANTHROPIC_API_KEY" not in os.environ:
                continue
            try:
                summary, source = fn(digest), name
                break
            except Exception as e:
                print(f"[narrate] {name} unavailable ({e}); trying next.", file=sys.stderr)
    if summary is None:
        summary = template_summary(digest)

    print("=== NeuralGuard weekly narrative ===")
    print(f"[{source}]\n")
    print(summary)
    print("\n" + DISCLAIMER)


if __name__ == "__main__":
    main()
