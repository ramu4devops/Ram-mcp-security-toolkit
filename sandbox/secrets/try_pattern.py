#!/usr/bin/env python3
"""
try_pattern.py -- a tiny sandbox for testing what the scanner would do with
a single line of code, WITHOUT running a full repo scan.

You will use this in three situations:

  1. "Does it catch OUR company's token format?"
        Before trusting a scan, paste one of your internal tokens and check.

  2. "Why didn't it flag this line?"
        Paste the line and see which check passed or failed, and why.

  3. "Why DID it flag this line? It's harmless."
        Same thing in reverse -- see which rule fired so you know what to tune.

Usage:
    python3 try_pattern.py 'API_TOKEN = "abc123def456"'
    python3 try_pattern.py --value 'sk-abc123'
    echo 'x = "..."' | python3 try_pattern.py
"""
import sys, argparse
from secrets_lib import (scan_line_for_secrets, is_placeholder, looks_random,
                         shannon_entropy, redact, GENERIC_ASSIGNMENT)


def explain_line(line):
    print(f"\nLine: {line.strip()}")
    print("-" * 70)
    hits = scan_line_for_secrets(line)
    if hits:
        print("RESULT: would be FLAGGED\n")
        for h in hits:
            print(f"  rule      : {h['name']}")
            print(f"  severity  : {h['severity']}   confidence: {h['confidence']}")
            print(f"  shown as  : {redact(h['value'])}\n")
        return
    print("RESULT: would NOT be flagged\n")
    print("  Why not -- walking the checks in order:")
    m = GENERIC_ASSIGNMENT.search(line)
    if not m:
        print("   1. No known provider format (AKIA…, ghp_…, sk-ant-…, etc.) in this line.")
        print("   2. No variable name containing a secret word")
        print("      (api_key / secret / password / pass / pwd / token / credential …).")
        print("      -> If your org uses a different word, add it to GENERIC_ASSIGNMENT")
        print("         in secrets_lib.py, or add a full pattern to PROVIDER_PATTERNS.")
        return
    val = m.group("val")
    print(f"   1. Variable name matched: '{m.group('name')}'")
    print(f"   2. Value found          : {redact(val)}  (length {len(val)})")
    if is_placeholder(val):
        print("   3. But the value looks like a PLACEHOLDER (example/fill-me-in text),")
        print("      so it was deliberately ignored. This is not a bug.")
        return
    ent = shannon_entropy(val.strip("\"'"))
    print(f"   3. Not a placeholder. Entropy = {ent:.2f} bits/char (need >= 3.20)")
    if len(val) < 16:
        print(f"   4. Value is only {len(val)} chars -- needs >= 16 to be treated as random.")
    elif ent < 3.2:
        print("   4. Entropy too low -- looks like a word/phrase, not a generated credential.")
    print("      -> If this IS a real secret, lower the thresholds in looks_random().")


def explain_value(val):
    print(f"\nValue: {val}")
    print("-" * 70)
    print(f"  placeholder?  {is_placeholder(val)}")
    print(f"  entropy       {shannon_entropy(val):.2f} bits/char")
    print(f"  length        {len(val)}")
    print(f"  looks random? {looks_random(val)}")
    print(f"  redacted as   {redact(val)}")
    hits = scan_line_for_secrets(f'secret = "{val}"')
    print(f"  as a line     {'FLAGGED: ' + hits[0]['name'] if hits else 'not flagged'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("line", nargs="?", help="a line of code to test")
    ap.add_argument("--value", help="test a bare value instead of a whole line")
    args = ap.parse_args()
    if args.value:
        explain_value(args.value)
    elif args.line:
        explain_line(args.line)
    else:
        data = sys.stdin.read().strip()
        if not data:
            ap.print_help(); sys.exit(2)
        for ln in data.splitlines():
            explain_line(ln)


if __name__ == "__main__":
    main()
