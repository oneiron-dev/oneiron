#!/usr/bin/env python3
"""Mac PowerPoint deck oracle. No engine imports and no network access.

Stage a private copy inside PowerPoint's container and never quit the app here.
Repair, permission prompts, and unrelated open decks cannot be clean opens.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import uuid
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
APP = Path('/Applications/Microsoft PowerPoint.app')
BUNDLE = 'com.microsoft.Powerpoint'
VERSION = 'one-2531-v1'
REPAIR_WORDS = ('repair', 'repaired', 'recover', 'corrupt', 'damaged', 'problem with content')
UNSUPPORTED_WORDS = ('grant file access', 'permission', 'sign in', 'activate office')
STAGING = Path.home() / 'Library/Containers/com.microsoft.Powerpoint/Data/tmp/w8-oracle'


def has_header(path: Path, header: bytes) -> bool:
    with path.open('rb') as file:
        return file.read(len(header)) == header


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def command(args: list[str], timeout: int = 8) -> str:
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if r.returncode:
        raise RuntimeError(f'{args[0]} exit {r.returncode}: {r.stderr.strip()}')
    return r.stdout.strip()


def env_pin(observer: str) -> dict:
    info = command(['/usr/libexec/PlistBuddy', '-c', 'Print CFBundleShortVersionString',
                    str(APP / 'Contents/Info.plist')])
    fonts = command(['atsutil', 'fonts', '-list'], timeout=30)
    return {'harness': VERSION, 'powerpoint': info,
            'macos': command(['sw_vers', '-productVersion']),
            'macos_build': command(['sw_vers', '-buildVersion']),
            'pdfkit': platform.mac_ver()[0], 'raster_scale': 2,
            'font_inventory_sha256': hashlib.sha256(fonts.encode()).hexdigest(),
            'observer': observer, 'locale': os.environ.get('LANG', '')}


def observer_status(observer: str) -> str | None:
    if observer == 'cua':
        if not shutil.which('cua-driver'):
            return 'cua-driver is not installed'
        try:
            obj = json.loads(command(['cua-driver', 'permissions', 'status', '--json']))
            # The CLI response layout varies across driver versions; window query
            # remains the decisive live capability test below.
            command(['cua-driver', 'call', 'list_windows', '{"pid":0}'])
            if obj.get('accessibility') is False:
                return 'CuaDriver Accessibility access is missing'
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            return f'CuaDriver observer unavailable: {exc}'
    else:
        try:
            command(['osascript', '-e', 'tell application "System Events" to get name of every process'], 5)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            return f'osascript Accessibility access is missing: {exc}'
    return None


def app_pid() -> int | None:
    r = subprocess.run(['pgrep', '-x', 'Microsoft PowerPoint'], capture_output=True, text=True)
    return int(r.stdout.splitlines()[0]) if r.returncode == 0 and r.stdout.strip() else None


def windows(observer: str, pid: int) -> list[str]:
    if observer == 'cua':
        data = json.loads(command(['cua-driver', 'call', 'list_windows', json.dumps({'pid': pid})], 6))
        return [w['title'] for w in data['windows'] if w.get('title')]
    script = 'tell application "System Events"\n    tell process "Microsoft PowerPoint"\n        set labels to {}\n        repeat with w in every window\n            set windowTitle to name of w\n            if windowTitle is not missing value then set end of labels to windowTitle as text\n            if subrole of w is "AXDialog" then\n                repeat with textEntry in (value of every static text of w)\n                    if textEntry is not missing value then set end of labels to textEntry as text\n                end repeat\n            end if\n        end repeat\n    end tell\nend tell\nset AppleScript\'s text item delimiters to (ASCII character 10)\nset resultText to labels as text\nset AppleScript\'s text item delimiters to ""\nreturn resultText'
    return [x.strip() for x in command(['osascript', '-e', script], 5).splitlines() if x.strip()]


def dialog_class(titles: list[str], expected_stem: str) -> str | None:
    unrelated = []
    for title in titles:
        low = title.lower()
        if any(word in low for word in REPAIR_WORDS):
            return 'repaired'
        if any(word in low for word in UNSUPPORTED_WORDS):
            return 'unsupported'
        if low not in (expected_stem.lower(), expected_stem.lower() + '.pptx',
                       'reference', 'reference.pptx', '', 'presentation1'):
            unrelated.append(title)
    return 'unsupported' if unrelated else None


def run_script(source: Path, action: str, target: Path | None, observer: str,
               deadline: float) -> tuple[str | None, str]:
    args = ['osascript', str(ROOT / 'powerpoint.applescript'), action, str(source)]
    if target:
        args.append(str(target))
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    classification = None
    while proc.poll() is None:
        pid = app_pid()
        if pid:
            try:
                classification = dialog_class(windows(observer, pid), source.stem)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                classification = 'unsupported'
                detail = f'observer failed: {exc}'
                break
            if classification:
                detail = f'PowerPoint window: {windows(observer, pid)}'
                break
        if time.monotonic() >= deadline:
            classification, detail = 'timed_out', f'{action} exceeded deadline'
            break
        time.sleep(0.25)
    if classification:
        proc.terminate()
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        return classification, detail
    out, err = proc.communicate()
    if proc.returncode:
        return 'failed', (err or out).strip()[-500:]
    # One final observation catches asynchronous dialogs after AppleScript returns.
    pid = app_pid()
    if pid:
        try:
            classification = dialog_class(windows(observer, pid), source.stem)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            return 'unsupported', f'observer failed: {exc}'
    return classification, out.strip()


def presentations() -> list[str]:
    """PowerPoint document inventory, independent of visible windows/dialogs."""
    text = command(['osascript', str(ROOT / 'powerpoint.applescript'), 'custody'], 8)
    return text.splitlines() if text else []


def custody(names: list[str], allowed: set[str]) -> str | None:
    """No foreign presentations, including saved ones with ordinary window titles."""
    foreign = [name for name in names if name not in allowed]
    if foreign:
        return f'unrelated open presentation(s): {foreign}'
    if len(names) > 1 or len(names) != len(set(names)):
        return f'ambiguous presentation custody: {names}'
    return None


def hide_powerpoint() -> None:
    if app_pid():
        command(['osascript', '-e',
                 'tell application "System Events" to set visible of process "Microsoft PowerPoint" to false'], 8)


def launch_hidden() -> None:
    if not app_pid():
        command(['open', '-g', '-j', '-a', 'Microsoft PowerPoint'], 15)
    hide_powerpoint()


def cancel_owned_repair(staged: Path) -> None:
    """Cancel only the observed repair alert naming our staged deck; never repair or grant access."""
    script = 'on run argv\n    tell application "System Events"\n        tell process "Microsoft PowerPoint"\n            repeat with w in every window\n                if subrole of w is "AXDialog" then\n                    set lines to value of every static text of w\n                    set AppleScript\'s text item delimiters to " "\n                    set messageText to lines as text\n                    set AppleScript\'s text item delimiters to ""\n                    if messageText contains (item 1 of argv) and messageText contains "PowerPoint can attempt to repair" then\n                        click button "Cancel" of w\n                        return "cancelled owned repair alert"\n                    end if\n                end if\n            end repeat\n        end tell\n    end tell\n    error "owned repair alert not found; no UI action taken"\nend run'
    command(['osascript', '-e', script, str(staged)], 8)
    hide_powerpoint()


def close_owned(allowed: set[str]) -> str | None:
    """Never close a presentation unless custody still identifies only ours."""
    if not app_pid():
        return None
    try:
        names = presentations()
        problem = custody(names, allowed)
        if problem:
            return problem
        if names:
            command(['osascript', str(ROOT / 'powerpoint.applescript'), 'close', names[0]], 10)
        hide_powerpoint()
        remaining = presentations()
        return f'presentation(s) remain open: {remaining}' if remaining else None
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return f'could not confirm presentation closure: {exc}'


def quit_if_empty() -> None:
    """Batch runner's one cooperative quit; never close someone else's documents."""
    if not app_pid():
        return
    names = presentations()
    if names:
        raise RuntimeError(f'refusing to quit PowerPoint with open presentations: {names}')
    command(['osascript', '-e', 'tell application "Microsoft PowerPoint" to quit'], 10)


def oracle(candidate: Path, output: Path, observer: str = 'system-events', timeout: int = 90) -> dict:
    candidate = candidate.resolve()
    output = output.resolve()
    receipt = {'status': 'unsupported', 'detail': '', 'input': {'sha256': digest(candidate),
               'bytes': candidate.stat().st_size}, 'outputs': {}, 'environment': None}
    output.mkdir(parents=True, exist_ok=False)
    stage = None
    allowed: set[str] = set()
    opened = False

    def record() -> dict:
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        return receipt

    if sys.platform != 'darwin' or not APP.exists():
        receipt['detail'] = 'PowerPoint for Mac not installed (macOS-only oracle)'
        return record()
    reason = observer_status(observer)
    if reason:
        receipt['detail'] = reason
        return record()
    try:
        # The preflight cannot be inferred from window titles. An unrelated saved
        # deck is a document even when its window happens to be hidden.
        if app_pid():
            names = presentations()
            if names:
                receipt['detail'] = f'PowerPoint has open presentation(s): {names}'
                return record()
        receipt['environment'] = env_pin(observer)
        stage = STAGING / f'{candidate.stem}-{os.getpid()}-{uuid.uuid4().hex[:8]}'
        stage.mkdir(parents=True, exist_ok=False)
        staged = stage / f'{candidate.stem}-{os.getpid()}-{uuid.uuid4().hex[:8]}.pptx'
        allowed = {staged.name, staged.stem, 'reference.pptx', 'reference'}
        shutil.copyfile(candidate, staged)
        receipt['staged_input_sha256'] = digest(staged)
        launch_hidden()
        if names := presentations():
            receipt['detail'] = f'PowerPoint has open presentation(s): {names}'
            return record()
        deadline = time.monotonic() + timeout
        for action in ('open', 'pdf', 'raster', 'saveback'):
            if action == 'raster':
                try:
                    swift = command(['swift', str(ROOT / 'raster.swift'), str(stage / 'render.pdf'),
                                     str(stage)], max(1, int(deadline - time.monotonic())))
                    pngs = sorted(stage.glob('page-*.png'))
                    if not pngs:
                        raise ValueError('PDFKit returned no PNG pages')
                    if any(not has_header(p, b'\x89PNG\r\n\x1a\n') for p in pngs):
                        raise ValueError('PDFKit returned invalid PNG header')
                    receipt['pages'] = len(pngs)
                    receipt['raster_detail'] = swift
                    for png in pngs:
                        shutil.move(str(png), output / png.name)
                        receipt['outputs'][png.name] = {'sha256': digest(output / png.name),
                                                        'bytes': (output / png.name).stat().st_size}
                except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                    receipt.update(status='timed_out' if isinstance(exc, subprocess.TimeoutExpired) else 'failed',
                                   detail=f'raster: {exc}')
                    break
                continue
            target = stage / {'pdf': 'render.pdf', 'saveback': 'reference.pptx'}[action] if action != 'open' else None
            try:
                if action == 'open':
                    opened = True  # open may leave a modal or a presentation on failure
                status, detail = run_script(staged, action, target, observer, deadline)
            finally:
                hide_powerpoint()
            if status:
                receipt.update(status=status, detail=f'{action}: {detail}')
                break
            names = presentations()
            problem = custody(names, allowed)
            if problem or len(names) != 1:
                detail = problem or f'expected one owned presentation; found {names}'
                receipt.update(status='unsupported', detail=f'{action}: {detail}')
                break
            if target:
                end_wait = min(deadline, time.monotonic() + 5)
                while (not target.is_file() or target.stat().st_size == 0) and time.monotonic() < end_wait:
                    time.sleep(0.25)
                if not target.is_file() or target.stat().st_size == 0:
                    receipt.update(status='failed', detail=f'{action}: missing or empty output after save')
                    break
                if action == 'pdf' and not has_header(target, b'%PDF-'):
                    receipt.update(status='failed', detail='pdf: invalid PDF header')
                    break
                if action == 'saveback':
                    try:
                        with zipfile.ZipFile(target) as z:
                            if z.testzip() or not z.namelist():
                                raise ValueError('save-back ZIP invalid')
                    except (ValueError, zipfile.BadZipFile) as exc:
                        receipt.update(status='failed', detail=f'saveback: {exc}')
                        break
                # PDF must stay in the stage until PDFKit has rasterized it.
                if action == 'pdf':
                    shutil.copy2(target, output / target.name)
                else:
                    shutil.move(str(target), output / target.name)
                receipt['outputs'][target.name] = {'sha256': digest(output / target.name),
                                                   'bytes': (output / target.name).stat().st_size}
        else:
            receipt.update(status='clean', detail=f"PDFKit rasterized {receipt['pages']} page(s)")
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        receipt.update(status='timed_out' if isinstance(exc, subprocess.TimeoutExpired) else 'unsupported',
                       detail=f'oracle control failure: {exc}')
    finally:
        if opened:
            warning = None
            if receipt['status'] == 'repaired':
                try:
                    cancel_owned_repair(staged)
                except (RuntimeError, subprocess.TimeoutExpired) as exc:
                    warning = f'could not dismiss owned repair alert: {exc}'
            warning = warning or close_owned(allowed)
            if warning:
                receipt['cleanup_warning'] = warning
                receipt.update(status='unsupported', detail=warning)
        if stage is not None:
            try:
                shutil.rmtree(stage)
            except OSError as exc:
                receipt['cleanup_warning'] = f'could not remove staging directory: {exc}'
                receipt.update(status='unsupported', detail=receipt['cleanup_warning'])
        record()
    return receipt


def classify_manifest(manifest: Path, results: Path) -> dict:
    cases = json.loads(manifest.read_text())['cases']
    report = {'cases': [], 'counts': {}}
    for case in cases:
        path = results / case['id'] / 'receipt.json'
        receipt = json.loads(path.read_text()) if path.exists() else None
        actual = receipt['status'] if receipt else 'not_run'
        expected = case['expected_oracle']
        verdict = 'pass' if actual == expected else 'inconclusive' if actual in ('unsupported', 'timed_out', 'not_run') else 'fail'
        row = {'id': case['id'], 'expected': expected, 'actual': actual, 'verdict': verdict,
               'preservation': case['preservation']}
        report['cases'].append(row)
        report['counts'][verdict] = report['counts'].get(verdict, 0) + 1
    return report


def acquire(case_id: str, destination: Path) -> dict:
    """Fetch one pinned pair, never run it in the owner's login account."""
    manifest = json.loads((ROOT / 'pptarena.json').read_text())
    case = next((c for c in manifest['cases'] if c['id'] == case_id), None)
    if case is None:
        raise ValueError(f'unknown PPTArena case: {case_id}')
    destination.mkdir(parents=True, exist_ok=False)
    receipt = {'case': case_id, 'revision': manifest['revision'], 'files': {}}
    for kind in ('original', 'ground_truth'):
        item = case[kind]
        url = manifest['source'] + '/resolve/' + manifest['revision'] + '/' + urllib.parse.quote(item['path'], safe='/')
        path = destination / (kind + '.pptx')
        try:
            with urllib.request.urlopen(url, timeout=30) as response, path.open('wb') as out:
                while chunk := response.read(1024 * 1024):
                    out.write(chunk)
                    if out.tell() > 50 * 1024 * 1024:
                        raise ValueError('corpus file exceeds 50 MiB cap')
            actual = digest(path)
            if actual != item['sha256']:
                raise ValueError(f'{kind} hash mismatch: {actual}')
            receipt['files'][kind] = {'sha256': actual, 'bytes': path.stat().st_size}
        except Exception:
            path.unlink(missing_ok=True)
            raise
    (destination / 'acquisition.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    run = sub.add_parser('run', help='run isolated PowerPoint oracle; no Linux fallback')
    run.add_argument('candidate', type=Path)
    run.add_argument('output', type=Path, help='new directory; must not exist')
    run.add_argument('--observer', choices=('cua', 'system-events'), default='system-events')
    run.add_argument('--timeout', type=int, default=90)
    matrix = sub.add_parser('classify', help='classify recorded fixture receipts')
    matrix.add_argument('manifest', type=Path)
    matrix.add_argument('results', type=Path)
    fetch = sub.add_parser('acquire', help='download one pinned PPTArena pair (never opens it)')
    fetch.add_argument('case_id')
    fetch.add_argument('destination', type=Path, help='new directory; binaries are not committed')
    args = p.parse_args()
    if args.command == 'acquire':
        if args.destination.exists():
            p.error('destination must be new')
        print(json.dumps(acquire(args.case_id, args.destination), indent=2))
        return 0
    if args.command == 'classify':
        report = classify_manifest(args.manifest, args.results)
        print(json.dumps(report, indent=2))
        return 1 if report['counts'].get('fail') else 0
    if args.timeout < 1 or not args.candidate.is_file() or args.output.exists():
        p.error('candidate must exist, timeout positive, and output directory must be new')
    receipt = oracle(args.candidate, args.output, args.observer, args.timeout)
    print(json.dumps(receipt, indent=2))
    return 0 if receipt['status'] == 'clean' else 2


if __name__ == '__main__':
    sys.exit(main())
