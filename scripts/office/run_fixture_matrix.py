#!/usr/bin/env python3
"""Run the local deck fixture matrix serially; quit once with no documents."""
import argparse
import json
from pathlib import Path
import sys
import subprocess
from deck_oracle import APP, oracle, classify_manifest, quit_if_empty, app_pid


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('results', type=Path, help='new result directory')
    args = p.parse_args()
    if sys.platform != 'darwin' or not APP.exists():
        print('SKIP: macOS PowerPoint is not installed', file=sys.stderr)
        return 0
    args.results.mkdir(parents=True, exist_ok=False)
    manifest = Path(__file__).with_name('fixtures.json')
    cases = json.loads(manifest.read_text())['cases']
    already_running = app_pid() is not None
    quit_error = None
    try:
        for case in cases:
            timeout = 1 if case['id'] == 'timeout' else 35
            result = oracle(Path(__file__).with_name('fixtures') / case['file'],
                            args.results / case['id'], timeout=timeout)
            print(f"{case['id']}: {result['status']} — {result['detail']}", flush=True)
            if result.get('cleanup_warning') or result['status'] == 'unsupported':
                print('STOP: PowerPoint custody or environment is unsupported', file=sys.stderr)
                break
    finally:
        report = classify_manifest(manifest, args.results)
        (args.results / 'matrix.json').write_text(json.dumps(report, indent=2) + '\n')
        if not already_running:
            try:
                quit_if_empty()
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                quit_error = str(exc)
                print(f'PowerPoint left running: {exc}', file=sys.stderr)
    print(json.dumps(report['counts'], sort_keys=True))
    return 1 if quit_error or report['counts'].get('fail') or report['counts'].get('inconclusive') else 0


if __name__ == '__main__':
    raise SystemExit(main())
