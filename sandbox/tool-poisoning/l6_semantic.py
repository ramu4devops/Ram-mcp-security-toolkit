"""
l6_semantic.py -- OPTIONAL semantic layer. Fully offline.

Swap `load_classifier()` for a real local model when you want L6. The rest of
the file (how a classifier verdict becomes a finding) never changes.
"""
import os

def load_classifier():
    """Return a function text -> (label, score) where label in {BENIGN, MALICIOUS}.

    REAL (offline) version -- uncomment after you have downloaded the model
    to disk and set HF_HUB_OFFLINE=1 (see the guide):

        from transformers import (AutoTokenizer,
            AutoModelForSequenceClassification, pipeline)
        m = "ProtectAI/deberta-v3-small-prompt-injection-v2"
        tok = AutoTokenizer.from_pretrained(m)
        mdl = AutoModelForSequenceClassification.from_pretrained(m)
        clf = pipeline("text-classification", model=mdl, tokenizer=tok,
                       truncation=True, max_length=512)
        def run(text):
            r = clf(text)[0]
            label = "MALICIOUS" if r["label"].upper() in ("INJECTION","LABEL_1") else "BENIGN"
            return label, float(r["score"])
        return run
    """
    # STUB used for this demo so the fusion logic can be tested with no model.
    def run(text):
        t = text.lower()
        hit = any(k in t for k in ["ignore previous", "do not tell",
                                   "read ~/.ssh", "bcc", "credentials"])
        return ("MALICIOUS", 0.97) if hit else ("BENIGN", 0.95)
    return run


def l6_findings(tools, threshold=0.8):
    clf = load_classifier()
    out = []
    for t in tools:
        text = f"{t.get('name','')}: {t.get('description','')}"
        label, score = clf(text)
        if label == "MALICIOUS" and score >= threshold:
            out.append({
                "box": "BOX-01", "layer": "L6",
                "severity": "high",          # never auto-critical on its own
                "confidence": round(score, 3),
                "tool": t.get("name"),
                "message": "Model flagged description as likely prompt injection",
                "evidence": f"classifier={label} score={score:.2f}",
                "verdict_hint": "MANUAL",    # a lone L6 hit -> human review
            })
    return out


if __name__ == "__main__":
    import json, sys
    tools = json.load(open(sys.argv[1]))
    for f in l6_findings(tools):
        print(f"[{f['severity'].upper()}] {f['box']}/{f['layer']} "
              f"tool='{f['tool']}' conf={f['confidence']} -> {f['verdict_hint']}")
