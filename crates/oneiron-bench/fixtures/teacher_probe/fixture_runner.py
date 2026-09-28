#!/usr/bin/env python3
"""Protocol fixture, NOT a model implementation. Real checkpoint inference belongs to the model repo."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--checkpoint", required=True)
parser.add_argument("--probe", required=True)
args = parser.parse_args()
probe = json.loads(Path(args.probe).read_text())
result = json.loads((Path(args.checkpoint) / "output.json").read_text())
assert len(result["predictions"]) == len(probe["sentences"])
print(json.dumps(result))
