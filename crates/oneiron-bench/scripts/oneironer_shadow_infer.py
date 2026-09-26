#!/usr/bin/env python3
"""NER-only inference in the model repo's own Python environment.

Invoked by oneiron-bench with a SHA-pinned external checkpoint. Never loads a
base encoder as a substitute for trained NER weights. The vault path is absent.
"""
import hashlib
import json
from pathlib import Path
import sys


def main():
    model_repo, checkpoint, expected_sha = (
        Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    )
    if not checkpoint.is_file():
        raise ValueError("trained NER checkpoint is required")
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    if digest != expected_sha:
        raise ValueError("NER checkpoint SHA-256 mismatch")
    if not (model_repo / "model" / "head_runtime.py").is_file():
        raise ValueError("model repository lacks the shared NER runtime")
    sys.path.insert(0, str(model_repo))
    from model.head_runtime import OneiroNERRuntime, _load_state

    state = _load_state(checkpoint)
    if not any(key.startswith("encoder.") for key in state):
        raise ValueError("NER checkpoint has no trained encoder")
    if "classifier.weight" not in state or "classifier.bias" not in state:
        raise ValueError("NER checkpoint has no trained classifier")
    request = json.load(sys.stdin)
    text = request["text"]
    if not isinstance(text, str):
        raise ValueError("turn text must be a string")
    runtime = OneiroNERRuntime(trunk_checkpoint=checkpoint, device="cpu")
    result = runtime.predict(text)
    if runtime.forward_count != 1 or result["ner"]["ckpt_sha256_16"] != digest[:16]:
        raise ValueError("NER checkpoint inference did not run exactly once")
    # The model uses Python character offsets; the engine's tag ABI uses UTF-8
    # byte offsets. Convert at this host boundary rather than dropping spans.
    boundaries = [len(text[:n].encode("utf-8")) for n in range(len(text) + 1)]
    spans = result["ner"]["spans"]
    for span in spans:
        span["start"] = boundaries[span["start"]]
        span["end"] = boundaries[span["end"]]
    json.dump(spans, sys.stdout, allow_nan=False)


if __name__ == "__main__":
    main()
