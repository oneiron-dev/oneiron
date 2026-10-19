#!/usr/bin/env python3
"""Mac PowerPoint deck oracle. No engine imports and no network access.

Stage a private copy inside PowerPoint's container and never quit the app here.
Repair, permission prompts, and unrelated open decks cannot be clean opens.
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import sys
import time
import uuid
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

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


def invalid_presentation_package(candidate: Path) -> bool:
    """Irrecoverable package/XML damage is a failed open even if Office offers Repair."""
    try:
        with zipfile.ZipFile(candidate) as archive:
            if archive.testzip():
                return True
            ET.fromstring(archive.read('ppt/presentation.xml'))
        return False
    except (zipfile.BadZipFile, KeyError, ET.ParseError, OSError):
        return True


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


# ---- font inventory: the font files on disk, per account -------------------
#
# The renderer's fonts are the files it can load: the system's, the machine's,
# the running account's and the ones the Office install carries. Each is
# identified by its bytes (SHA-256), never by mtime or by the session's
# activated list (`atsutil` reports on-demand activation, which differs per
# login session). A missing root or an unreadable file is a row of its own.
FONT_SUFFIXES = frozenset({'.ttf', '.otf', '.ttc', '.otc', '.dfont', '.fon', '.pfb', '.pfm',
                           '.afm', '.woff', '.woff2', '.suit'})
MISSING_ROOT = 'missing-root'
UNREADABLE = 'unreadable'


def font_account() -> str:
    """The effective OS account: whose ~/Library/Fonts PowerPoint loads."""
    return pwd.getpwuid(os.geteuid()).pw_name


def font_roots() -> list[tuple[str, Path]]:
    resources = APP / 'Contents/Resources'
    return [('system', Path('/System/Library/Fonts')), ('local', Path('/Library/Fonts')),
            ('user', Path.home() / 'Library/Fonts'), ('office-dfonts', resources / 'DFonts'),
            ('office-fonts', resources / 'Fonts')]


def font_file(path: Path) -> bool:
    """A font file: a known font suffix, or an extensionless resource (a suitcase)."""
    return not path.name.startswith('.') and (path.suffix.lower() in FONT_SUFFIXES or not path.suffix)


def inventory_rows() -> list[dict]:
    """Sorted rows {root_label, relative_path, bytes, sha256} over every font root."""
    rows = []

    def problem(label: str, relative: str, why: str) -> None:
        rows.append({'root_label': label, 'relative_path': relative, 'bytes': None, 'sha256': why})

    for label, root in font_roots():
        if not root.is_dir():
            problem(label, '.', MISSING_ROOT)
            continue
        unreadable: list[OSError] = []
        for folder, _, names in os.walk(root, onerror=unreadable.append):
            for name in names:
                path = Path(folder) / name
                if not font_file(path) or not path.is_file():
                    continue
                relative = path.relative_to(root).as_posix()
                try:
                    rows.append({'root_label': label, 'relative_path': relative,
                                 'bytes': path.stat().st_size, 'sha256': digest(path)})
                except OSError as exc:
                    problem(label, relative, f'{UNREADABLE}: {exc.strerror or exc}')
        for exc in unreadable:
            where = Path(exc.filename).relative_to(root).as_posix() if exc.filename else '.'
            problem(label, where, f'{UNREADABLE}: {exc.strerror or exc}')
    return sorted(rows, key=lambda row: (row['root_label'], row['relative_path']))


def inventory_digest(rows: list[dict]) -> str:
    """SHA-256 of the rows as canonical UTF-8 JSON."""
    canonical = json.dumps(rows, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


@functools.lru_cache(maxsize=1)
def font_inventory() -> tuple[str, str, tuple]:
    """(account, digest, rows), measured once per process: one Office pass shares it."""
    rows = inventory_rows()
    return font_account(), inventory_digest(rows), tuple(rows)


def inventory_problems(rows) -> list[str]:
    return [f"{row['root_label']}/{row['relative_path']}: {row['sha256']}" for row in rows
            if row['sha256'] == MISSING_ROOT or row['sha256'].startswith(UNREADABLE)]


def approve_command() -> str:
    """The exact command that approves this account's inventory, in the source checkout."""
    script, config = Path(__file__).resolve(), ROOT / 'environment.json'
    if ROOT.name == 'office' and ROOT.parent.name == 'scripts':
        return f'python3 -I {script} fonts --approve {config}'
    return ('python3 -I scripts/office/deck_oracle.py fonts --approve scripts/office/environment.json '
            '(from the source checkout, as this account; a run directory pins its copy, so approve '
            'in source and start a new run)')


def env_pin(observer: str) -> dict:
    info = command(['/usr/libexec/PlistBuddy', '-c', 'Print CFBundleShortVersionString',
                    str(APP / 'Contents/Info.plist')])
    account, inventory, _ = font_inventory()
    return {'harness': VERSION, 'powerpoint': info,
            'macos': command(['sw_vers', '-productVersion']),
            'macos_build': command(['sw_vers', '-buildVersion']),
            'pdfkit': platform.mac_ver()[0], 'raster_scale': 2,
            'font_account': account, 'font_inventory_sha256': inventory,
            'observer': observer, 'locale': os.environ.get('LANG', '')}


ENV_FIELDS = frozenset({'harness', 'powerpoint', 'macos', 'macos_build', 'pdfkit',
                        'raster_scale', 'observer', 'locale'})
ENV_VERSION = 2


def environment_mismatch(observed: dict) -> str | None:
    """Only the explicitly approved Mac/renderer combination may produce a clean receipt.
    Fonts are judged against the account the receipt records, not the one reading it."""
    try:
        config = json.loads((ROOT / 'environment.json').read_text())
        expected = config['environment']
        approved = config['approved_font_inventories']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return f'approved environment unavailable: {exc}'
    if (config.get('version') != ENV_VERSION or not isinstance(expected, dict)
            or set(expected) != ENV_FIELDS or not isinstance(approved, dict)):
        return 'approved environment configuration is incomplete or unsupported'
    if not isinstance(observed, dict):
        return 'no environment was recorded'
    for field in sorted(ENV_FIELDS):
        if observed.get(field) != expected[field]:
            return f'unapproved environment {field}: expected {expected[field]!r}, observed {observed.get(field)!r}'
    account, inventory = observed.get('font_account'), observed.get('font_inventory_sha256')
    if not account or not inventory:
        return 'the environment records no font account or font inventory'
    if approved.get(account) != inventory:
        held = approved.get(account)
        why = (f'approved {held}' if held else 'none approved')
        return (f'unapproved font inventory for account {account!r}: observed {inventory}, {why}; '
                f'inspect with `deck_oracle.py fonts`, then approve as {account} with: {approve_command()}')
    return None


def write_json_atomic(path: Path, value) -> None:
    aside = path.with_name(path.name + '.part')
    with aside.open('w') as out:
        out.write(json.dumps(value, indent=2, sort_keys=True) + '\n')
        out.flush()
        os.fsync(out.fileno())
    os.replace(aside, path)


def fonts(approve: Path | None) -> int:
    """Print this account's font inventory and digest; with --approve, record it."""
    account, inventory, rows = font_inventory()
    for row in rows:
        print(json.dumps(row, sort_keys=True, ensure_ascii=False))
    problems = inventory_problems(rows)
    for problem in problems:
        print(f'WARNING {problem}', file=sys.stderr)
    print(f'account {account} font_inventory_sha256 {inventory} ({len(rows)} rows, '
          f'{len(problems)} missing or unreadable)')
    if approve is None:
        return 0
    config = json.loads(approve.read_text())
    if config.get('version') != ENV_VERSION or not isinstance(config.get('approved_font_inventories'), dict):
        print(f'REFUSED: {approve} is not a version {ENV_VERSION} environment', file=sys.stderr)
        return 2
    config['approved_font_inventories'][account] = inventory
    write_json_atomic(approve, config)
    print(f'approved {account} -> {inventory} in {approve}')
    return 0


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


def windows(observer: str, pid: int, timeout: float | None = None) -> list[str]:
    if observer == 'cua':
        data = json.loads(command(['cua-driver', 'call', 'list_windows', json.dumps({'pid': pid})],
                                  min(6, timeout) if timeout is not None else 6))
        return ['WINDOW:' + w['title'] for w in data['windows'] if w.get('title')]
    script = 'tell application "System Events"\n    tell process "Microsoft PowerPoint"\n        set labels to {}\n        repeat with w in every window\n            set windowKind to "WINDOW:"\n            if subrole of w is "AXDialog" then set windowKind to "DIALOG:"\n            set windowTitle to name of w\n            if windowTitle is not missing value then set end of labels to windowKind & (windowTitle as text)\n            if windowKind is "DIALOG:" then\n                set textValues to get value of every static text of w\n                repeat with textEntry in textValues\n                    set actualText to contents of textEntry\n                    if actualText is not missing value then set end of labels to "DIALOG:" & (actualText as text)\n                end repeat\n            end if\n        end repeat\n    end tell\nend tell\nset AppleScript\'s text item delimiters to (ASCII character 30)\nset resultText to labels as text\nset AppleScript\'s text item delimiters to ""\nreturn resultText'
    text = command(['osascript', '-e', script], min(5, timeout) if timeout is not None else 5)
    return [entry.strip() for entry in text.split('\x1e') if entry.strip()]


def dialog_class(titles: list[str], expected_stem: str) -> str | None:
    allowed = {expected_stem.lower(), expected_stem.lower() + '.pptx',
               'reference', 'reference.pptx', '', 'presentation1'}
    unrelated = []
    for title in titles:
        kind, separator, text = title.partition(':')
        if not separator or kind not in ('WINDOW', 'DIALOG'):
            return 'unsupported'
        low = text.lower()
        # An exact document title is not a repair prompt, even if its name
        # contains "recovery", "repair", or "permission".
        if low in allowed:
            continue
        if kind != 'WINDOW':
            if any(word in low for word in REPAIR_WORDS):
                return 'repaired'
            if any(word in low for word in UNSUPPORTED_WORDS):
                return 'unsupported'
        unrelated.append(title)
    return 'unsupported' if unrelated else None


def stop_script(proc: subprocess.Popen) -> None:
    """Reap the scripting child even if the oracle budget is already exhausted."""
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()


def run_script(source: Path, action: str, target: Path | None, observer: str,
               deadline: float) -> tuple[str | None, str]:
    if time.monotonic() >= deadline:
        return 'timed_out', f'{action} exceeded deadline before launch'
    args = ['osascript', str(ROOT / 'powerpoint.applescript'), action, str(source)]
    if target:
        args.append(str(target))
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    classification = None
    detail = ''
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            classification, detail = 'timed_out', f'{action} exceeded deadline'
            break
        if proc.poll() is not None:
            break
        pid = app_pid()
        if pid:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                classification, detail = 'timed_out', f'{action} exceeded deadline'
                break
            try:
                observed = windows(observer, pid, remaining)
                classification = dialog_class(observed, source.stem)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                classification, detail = 'unsupported', f'observer failed: {exc}'
                break
            if time.monotonic() >= deadline:
                classification, detail = 'timed_out', f'{action} exceeded deadline'
                break
            if classification:
                detail = f'PowerPoint window: {observed}'
                break
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    if classification:
        stop_script(proc)
        return classification, detail
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        stop_script(proc)
        return 'timed_out', f'{action} exceeded deadline after process exit'
    try:
        out, err = proc.communicate(timeout=remaining)
    except subprocess.TimeoutExpired:
        stop_script(proc)
        return 'timed_out', f'{action} exceeded deadline while collecting output'
    if time.monotonic() >= deadline:
        return 'timed_out', f'{action} exceeded deadline after process exit'
    if proc.returncode:
        return 'failed', (err or out).strip()[-500:]
    pid = app_pid()
    if pid:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 'timed_out', f'{action} exceeded deadline before final observation'
        try:
            observed = windows(observer, pid, remaining)
            classification = dialog_class(observed, source.stem)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            return 'unsupported', f'observer failed: {exc}'
    if time.monotonic() >= deadline:
        return 'timed_out', f'{action} exceeded deadline after observation'
    return classification, out.strip()


# Seconds PowerPoint has to answer the custody query.
CUSTODY_QUERY_SECONDS = 8


class CustodyTimeout(subprocess.TimeoutExpired):
    """PowerPoint left the custody query unanswered: the environment, not the deck."""


def presentations() -> list[str]:
    """PowerPoint document inventory, independent of visible windows/dialogs."""
    try:
        text = command(['osascript', str(ROOT / 'powerpoint.applescript'), 'custody'], CUSTODY_QUERY_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise CustodyTimeout(exc.cmd, exc.timeout, exc.output, exc.stderr) from exc
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
    script = 'on run argv\n    tell application "System Events"\n        tell process "Microsoft PowerPoint"\n            repeat with w in every window\n                if subrole of w is "AXDialog" then\n                    set messageText to ""\n                    set textValues to get value of every static text of w\n                    repeat with textEntry in textValues\n                        set actualText to contents of textEntry\n                        if actualText is not missing value then set messageText to messageText & " " & (actualText as text)\n                    end repeat\n                    if messageText contains (item 1 of argv) and messageText contains "PowerPoint can attempt to repair" then\n                        click button "Cancel" of w\n                        return "cancelled owned repair alert"\n                    end if\n                end if\n            end repeat\n        end tell\n    end tell\n    error "owned repair alert not found; no UI action taken"\nend run'
    command(['osascript', '-e', script, str(staged)], 8)
    hide_powerpoint()


def close_owned(allowed: set[str]) -> str | None:
    """Never close a foreign presentation, or overlook a modal after closing ours."""
    pid = app_pid()
    if not pid:
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
        if remaining:
            return f'presentation(s) remain open: {remaining}'
        observed = windows('system-events', pid)
        if any(entry.startswith('DIALOG:') for entry in observed) or any(
                dialog_class([entry], '') for entry in observed if not entry.startswith('WINDOW:')):
            return f'PowerPoint dialog remains after cleanup: {observed}'
        return None
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return f'could not confirm presentation/dialog closure: {exc}'


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
    repair_alert_seen = False

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
        mismatch = environment_mismatch(receipt['environment'])
        if mismatch:
            receipt['detail'] = mismatch
            return record()
        stage = STAGING / f'{candidate.stem}-{os.getpid()}-{uuid.uuid4().hex[:8]}'
        stage.mkdir(parents=True, exist_ok=False)
        staged = stage / f'{candidate.stem}-{os.getpid()}-{uuid.uuid4().hex[:8]}.pptx'
        allowed = {staged.name, staged.stem, 'reference.pptx', 'reference'}
        shutil.copyfile(candidate, staged)
        receipt['staged_input_sha256'] = digest(staged)
        if (receipt['staged_input_sha256'] != receipt['input']['sha256']
                or staged.stat().st_size != receipt['input']['bytes']):
            receipt['detail'] = 'input changed before staging; refusing a different snapshot'
            return record()
        launch_hidden()
        if names := presentations():
            receipt['detail'] = f'PowerPoint has open presentation(s): {names}'
            return record()
        deadline = time.monotonic() + timeout

        def expired(stage_name: str) -> bool:
            if time.monotonic() < deadline:
                return False
            receipt.update(status='timed_out', detail=f'{stage_name} exceeded deadline')
            return True

        for action in ('open', 'pdf', 'raster', 'saveback'):
            if expired(action):
                break
            if action == 'raster':
                try:
                    swift = command(['swift', str(ROOT / 'raster.swift'), str(stage / 'render.pdf'),
                                     str(stage)], deadline - time.monotonic())
                    if expired('raster'):
                        break
                    pngs = sorted(stage.glob('page-*.png'))
                    if not pngs:
                        raise ValueError('PDFKit returned no PNG pages')
                    if any(not has_header(p, b'\x89PNG\r\n\x1a\n') for p in pngs):
                        raise ValueError('PDFKit returned invalid PNG header')
                    receipt['pages'] = len(pngs)
                    receipt['raster_detail'] = swift
                    for png in pngs:
                        if expired('raster output'):
                            break
                        shutil.move(str(png), output / png.name)
                        receipt['outputs'][png.name] = {'sha256': digest(output / png.name),
                                                        'bytes': (output / png.name).stat().st_size}
                    if expired('raster output'):
                        break
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
            if expired(action):
                # A repair alert must still be cancelled during cleanup even if
                # the observer returned it at the boundary of the deadline.
                repair_alert_seen = status == 'repaired'
                break
            if status:
                repair_alert_seen = status == 'repaired'
                if repair_alert_seen and invalid_presentation_package(staged):
                    receipt.update(status='failed', detail=f'{action}: repair alert on invalid package/XML; refused')
                else:
                    receipt.update(status=status, detail=f'{action}: {detail}')
                break
            names = presentations()
            problem = custody(names, allowed)
            if problem or len(names) != 1:
                detail = problem or f'expected one owned presentation; found {names}'
                receipt.update(status='unsupported', detail=f'{action}: {detail}')
                break
            if target:
                if expired(action + ' validation'):
                    break
                end_wait = min(deadline, time.monotonic() + 5)
                while (not target.is_file() or target.stat().st_size == 0) and time.monotonic() < end_wait:
                    time.sleep(0.25)
                if expired(action + ' output wait'):
                    break
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
                if expired(action + ' postprocessing'):
                    break
        else:
            if not expired('final validation'):
                receipt.update(status='clean', detail=f"PDFKit rasterized {receipt['pages']} page(s)")
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        receipt.update(status='timed_out' if isinstance(exc, subprocess.TimeoutExpired) else 'unsupported',
                       detail=f'oracle control failure: {exc}')
        if isinstance(exc, CustodyTimeout):
            # The batch runner counts these; a run of them is an environment stop.
            receipt['custody_timeout'] = True
    finally:
        if opened:
            warning = None
            if repair_alert_seen:
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
        pinned = ({case['sha256']} if 'sha256' in case else
                  {case[role]['sha256'] for role in ('original', 'ground_truth')})
        path = results / case['id'] / 'receipt.json'
        receipt = json.loads(path.read_text()) if path.exists() else None
        actual = receipt.get('status', 'unsupported') if isinstance(receipt, dict) else 'not_run'
        expected = case['expected_oracle']
        inputs = receipt.get('input') if isinstance(receipt, dict) else None
        binding = inputs.get('sha256') if isinstance(inputs, dict) else None
        snapshot = receipt.get('staged_input_sha256') if isinstance(receipt, dict) else None
        # A clean or classified open requires proof of the bytes actually staged.
        # Preflight refusals can be unsupported, and custody or environment
        # timeouts timed out, before any staging took place: inconclusive,
        # never a binding failure.
        snapshot_error = (receipt is not None and
                          (snapshot is not None and snapshot != binding or
                           snapshot is None and actual not in ('unsupported', 'timed_out')))
        environment_error = (environment_mismatch(receipt.get('environment'))
                             if isinstance(receipt, dict) else None)
        if receipt is not None and (binding not in pinned or snapshot_error):
            verdict = 'fail'
        elif environment_error:
            verdict = 'inconclusive' if actual in ('unsupported', 'timed_out') else 'fail'
        elif actual == expected:
            verdict = 'pass'
        elif actual in ('unsupported', 'timed_out', 'not_run'):
            verdict = 'inconclusive'
        else:
            verdict = 'fail'
        row = {'id': case['id'], 'expected': expected, 'actual': actual, 'verdict': verdict,
               'preservation': case['preservation']}
        if receipt is not None and binding not in pinned:
            row['binding_error'] = 'receipt input SHA-256 missing or not pinned to this case'
        elif snapshot_error:
            row['binding_error'] = 'staged input SHA-256 missing or differs from receipt input'
        if environment_error:
            row['environment_error'] = environment_error
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
    font = sub.add_parser('fonts', help="print this account's font file inventory and its digest")
    font.add_argument('--approve', type=Path, metavar='ENVIRONMENT_JSON',
                      help="record this account's digest as approved in that environment.json")
    args = p.parse_args()
    if args.command == 'fonts':
        return fonts(args.approve)
    if args.command == 'acquire':
        if args.destination.exists():
            p.error('destination must be new')
        print(json.dumps(acquire(args.case_id, args.destination), indent=2))
        return 0
    if args.command == 'classify':
        report = classify_manifest(args.manifest, args.results)
        print(json.dumps(report, indent=2))
        return 1 if report['counts'].get('fail') or report['counts'].get('inconclusive') else 0
    if args.timeout < 1 or not args.candidate.is_file() or args.output.exists():
        p.error('candidate must exist, timeout positive, and output directory must be new')
    receipt = oracle(args.candidate, args.output, args.observer, args.timeout)
    print(json.dumps(receipt, indent=2))
    return 0 if receipt['status'] == 'clean' else 2


if __name__ == '__main__':
    sys.exit(main())
