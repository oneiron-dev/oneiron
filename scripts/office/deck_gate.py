#!/usr/bin/env python3
"""OF-510 deck gate, Office half (pptx-live-v1).

The engine half (`deck-gate-cases`, crates/oneiron-docedit) writes a run
directory: the candidates it exported through the current projector, each
pinned by SHA-256 with the checks PowerPoint owes it, the adversarial
calibration fixtures, the engine outcome of all eight steps, and a copy of
this script with deck_oracle.py and its pinned environment. This script opens
every candidate in the approved PowerPoint (deck_oracle's custody, staging,
environment pin and refusal rules, under the shared Office lock), inspects
PowerPoint's save-back for the intended change, and joins its outcomes to the
engine's into the OracleReceipt that `vault.artifacts.body.deck.oracle`
records. docs/ops/deck-gate.md has the commands.

  acquire REPO CORPUS  fetch the selected PPTArena originals; never opens one
  plan RUN             verify a run directory and say what `office` would open
  office RUN           Mac mini only: open everything serially, then assemble
  assemble RUN         join the Office results to the engine's; no Office

An unrun, timed-out or unsupported case is inconclusive, never a pass. A
custody or environment timeout before a deck was staged is the environment's,
not the deck's: inconclusive, never failed. After CUSTODY_TIMEOUTS_STOP custody
queries in a row go unanswered the pass stops with an environment verdict and
the rest stay unrun. The Office lock is released on every exit Python can
catch (SIGTERM and SIGHUP unwind like an exception; SIGKILL cannot be caught).
A run the engine half did not finish (a journal, results.jsonl, and no
manifest) is reported from its journal and refused for every command: no
Office pass and no receipt come from an incomplete run.
"""
from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import deck_oracle as oracle_mod  # noqa: E402  (beside this file, in the repo and in a run)

RUN_SCHEMA = 'oneiron.deck-gate-run/1'
JOURNAL = 'results.jsonl'
JOURNAL_SCHEMA = 'oneiron.deck-gate-journal/1'
PROFILE = 'pptx-live-v1'
CASE_MANIFEST = 'scripts/office/pptx-live-v1.json'
ORACLE, NON_PDF, REGRESSION = 6, 7, 8
OFFICE_STEPS = (ORACLE, NON_PDF, REGRESSION)
LOCK = Path.home() / 'w7-oracle' / 'lock'
# Consecutive PowerPoint custody queries that time out before an Office pass
# stops with an environment verdict (FIX 5230): the app, not the decks.
CUSTODY_TIMEOUTS_STOP = 3
# Signals held while the lock changes hands, and the ones that stop a pass.
HELD_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
STOP_SIGNALS = (signal.SIGTERM, signal.SIGHUP)
NAMED_CASES = 4
RANK = {'passed': 0, 'inconclusive': 1, 'failed': 2}

P = '{http://schemas.openxmlformats.org/presentationml/2006/main}'
A = '{http://schemas.openxmlformats.org/drawingml/2006/main}'
R = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}'
REL = '{http://schemas.openxmlformats.org/package/2006/relationships}'
P188 = '{http://schemas.microsoft.com/office/powerpoint/2018/8/main}'
COMMENT_REL = 'http://schemas.microsoft.com/office/2018/10/relationships/comments'
SHAPES = {P + 'sp', P + 'pic', P + 'graphicFrame', P + 'cxnSp', P + 'grpSp'}


# ---- step outcomes, in the gate's JSON shape -------------------------------

def outcome(kind: str, detail: str = ''):
    """`"passed"`, `{"failed": why}` or `{"inconclusive": why}`: StepOutcome."""
    return 'passed' if kind == 'passed' else {kind: detail}


def split(value) -> tuple[str, str]:
    if value == 'passed':
        return 'passed', ''
    if value == 'not_run':
        return 'inconclusive', 'not run'
    if isinstance(value, dict) and len(value) == 1:
        kind, detail = next(iter(value.items()))
        if kind in ('failed', 'inconclusive'):
            return kind, str(detail)
    return 'failed', f'unreadable step outcome {value!r}'


def aggregate(rows: list[tuple[str, tuple[str, str]]]):
    """A step's Office half: every case passed, else the failures, else the open cases."""
    if not rows:
        return outcome('inconclusive', 'no Office case')
    for kind in ('failed', 'inconclusive'):
        named = [f'{case}: {detail}' for case, (verdict, detail) in rows if verdict == kind]
        if named:
            more = f' (+{len(named) - NAMED_CASES} more)' if len(named) > NAMED_CASES else ''
            return outcome(kind, '; '.join(named[:NAMED_CASES]) + more)
    return outcome('passed')


def worst(engine, office):
    (ek, ed), (ok, od) = split(engine), split(office)
    if ek == ok == 'passed':
        return outcome('passed')
    kind = ek if RANK[ek] >= RANK[ok] else ok
    details = [f'{side}: {detail}' for side, k, detail in (('engine', ek, ed), ('office', ok, od)) if k == kind]
    return outcome(kind, '; '.join(details))


# ---- the run directory -----------------------------------------------------

def load_run(run: Path) -> dict:
    """The run manifest. Without one, a journal is reported and the run refused."""
    manifest = run / 'manifest.json'
    if manifest.is_file():
        return json.loads(manifest.read_text())
    if (run / JOURNAL).is_file():
        report_partial(run)
        print(f'REFUSED: {run} is incomplete (no manifest.json): the engine half stopped before '
              'it finished. No Office pass and no approval come from an incomplete run; run the '
              'engine half again.', file=sys.stderr)
    else:
        print(f'REFUSED: {run} holds neither manifest.json nor {JOURNAL}', file=sys.stderr)
    raise SystemExit(2)


def report_partial(run: Path) -> None:
    """What a cut-short run finished, from its journal's complete lines only."""
    lines = (run / JOURNAL).read_text(errors='replace').splitlines()
    header, cases, torn = None, [], 0
    for at, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            torn += 1  # a line cut by the stop: the case in progress, never counted
            continue
        if at == 0 and entry.get('line') == 'header' and entry.get('schema') == JOURNAL_SCHEMA:
            header = entry
        elif entry.get('line') == 'case':
            cases.append(entry)
    if header is None:
        print(f'{run / JOURNAL}: no {JOURNAL_SCHEMA} header; nothing to report', file=sys.stderr)
        return
    print(f"PARTIAL run {run}: profile {header.get('profile')}, projector {header.get('projector')}, "
          f"source {header.get('source')}")
    counts: dict[str, int] = {}
    for case in cases:
        kind, _ = split(case.get('outcome'))
        counts[kind] = counts.get(kind, 0) + 1
    print(f"{len(cases)} cases finished: " + ', '.join(f'{n} {kind}' for kind, n in sorted(counts.items()))
          + (f'; {torn} unreadable line(s) not counted' if torn else ''))
    steps: dict[int, dict[str, int]] = {}
    for case in cases:
        for result in case.get('results', []):
            kind, _ = split(result.get('outcome'))
            row = steps.setdefault(result.get('step'), {})
            row[kind] = row.get(kind, 0) + 1
    for step in sorted(s for s in steps if isinstance(s, int)):
        print(f"step {step}: " + ', '.join(f'{n} {kind}' for kind, n in sorted(steps[step].items())))
    for case in cases:
        kind, detail = split(case.get('outcome'))
        if kind != 'passed':
            print(f"  {case.get('id')} {kind} ({case.get('elapsed_ms')} ms): {detail}")
    candidates = sum(len(case.get('candidates', [])) for case in cases)
    print(f'{candidates} candidates written by finished cases')


def verify(run: Path, manifest: dict) -> list[str]:
    """Every pinned file of the run is present with its bytes; nothing is opened."""
    problems = []
    if manifest.get('schema') != RUN_SCHEMA:
        problems.append(f"schema {manifest.get('schema')!r} is not {RUN_SCHEMA}")
    if manifest.get('profile') != PROFILE:
        problems.append(f"profile {manifest.get('profile')!r} is not {PROFILE}")
    if [step.get('step') for step in manifest.get('steps', [])] != list(range(1, 9)):
        problems.append('the manifest does not hold the eight steps in canon order')
    entries = manifest.get('candidates', []) + manifest.get('calibration', [])
    ids = [entry['id'] for entry in manifest.get('candidates', [])]
    if len(ids) != len(set(ids)):
        problems.append('candidate ids repeat')
    for entry in entries:
        path = run / entry['file']
        if not path.is_file():
            problems.append(f"{entry['id']}: {entry['file']} is missing")
        elif path.stat().st_size != entry['bytes'] or oracle_mod.digest(path) != entry['sha256']:
            problems.append(f"{entry['id']}: {entry['file']} does not match its pin")
    for script in manifest.get('office', {}).get('scripts', []):
        path = run / script['path']
        if not path.is_file() or oracle_mod.digest(path) != script['sha256']:
            problems.append(f"{script['path']} does not match its pin")
    return problems


# ---- PowerPoint's save-back ------------------------------------------------

def resolve(source: str, target: str) -> str:
    if target.startswith('/'):
        return target[1:]
    parts = (source.rsplit('/', 1)[0].split('/') if '/' in source else []) + target.split('/')
    out: list[str] = []
    for part in parts:
        if part == '..':
            if out:
                out.pop()
        elif part and part != '.':
            out.append(part)
    return '/'.join(out)


def rels_name(source: str) -> str:
    if not source:
        return '_rels/.rels'
    folder, _, name = source.rpartition('/')
    return f'{folder}/_rels/{name}.rels' if folder else f'_rels/{name}.rels'


class SaveBack:
    """The reference .pptx PowerPoint saved: what PowerPoint itself read."""

    def __init__(self, path: Path):
        self.zip = zipfile.ZipFile(path)
        presentation = next(target for kind, target in self.rels('').values()
                            if kind.endswith('/officeDocument'))
        tree = ET.fromstring(self.zip.read(presentation))
        rels = self.rels(presentation)
        listed = tree.find(P + 'sldIdLst')
        self.slides = [rels[entry.get(R + 'id')][1] for entry in (listed if listed is not None else [])]

    def rels(self, source: str) -> dict:
        try:
            data = self.zip.read(rels_name(source))
        except KeyError:
            return {}
        out = {}
        for rel in ET.fromstring(data).iter(REL + 'Relationship'):
            target = rel.get('Target', '')
            external = rel.get('TargetMode') == 'External'
            out[rel.get('Id')] = (rel.get('Type', ''), target if external else resolve(source, target))
        return out

    def part(self, slide: int) -> str:
        if slide < 1:
            raise IndexError(f'slide {slide}')
        return self.slides[slide - 1]

    def tree(self, slide: int):
        return ET.fromstring(self.zip.read(self.part(slide)))

    def markup(self, slide: int) -> str:
        return self.zip.read(self.part(slide)).decode('utf-8', 'replace')

    def text(self, slide: int) -> str:
        return '\n'.join(''.join(run.text or '' for run in paragraph.iter(A + 't'))
                         for paragraph in self.tree(slide).iter(A + 'p'))

    def shapes(self, slide: int) -> dict:
        found = {}
        for element in self.tree(slide).iter():
            if element.tag not in SHAPES or not len(element):
                continue
            props = element[0].find(P + 'cNvPr')
            if props is not None and (props.get('id') or '').isdigit():
                found[int(props.get('id'))] = element
        return found

    @staticmethod
    def offset(element):
        for path in (P + 'spPr/' + A + 'xfrm', P + 'xfrm', P + 'grpSpPr/' + A + 'xfrm'):
            frame = element.find(path)
            if frame is not None and frame.find(A + 'off') is not None:
                off = frame.find(A + 'off')
                return int(off.get('x')), int(off.get('y'))
        return None

    def comments(self, slide: int) -> list[str]:
        texts = []
        for kind, target in self.rels(self.part(slide)).values():
            if kind != COMMENT_REL:
                continue
            for comment in ET.fromstring(self.zip.read(target)).iter(P188 + 'cm'):
                texts.append(''.join(run.text or '' for run in comment.iter(A + 't')))
        return texts

    def timing(self, slide: int, spid: int) -> tuple[bool, list[tuple[int, int]]]:
        found, ranges = False, []
        for target in self.tree(slide).iter(P + 'spTgt'):
            if target.get('spid') != str(spid):
                continue
            found = True
            span = target.find(P + 'txEl/' + P + 'pRg')
            if span is not None:
                ranges.append((int(span.get('st')), int(span.get('end'))))
        return found, ranges


def evaluate(check: dict, deck: SaveBack, receipt: dict) -> str | None:
    """None when PowerPoint's save-back shows what the check says; else why not."""
    kind = check['check']
    try:
        if kind == 'pages':
            return None if receipt.get('pages') == check['count'] else \
                f"PDFKit rasterized {receipt.get('pages')} pages, {check['count']} expected"
        if kind == 'slides':
            return None if len(deck.slides) == check['count'] else \
                f"PowerPoint saved {len(deck.slides)} slides, {check['count']} expected"
        slide = check['slide']
        if kind == 'text':
            return None if check['contains'] in deck.text(slide) else \
                f"slide {slide} lost the text {check['contains']!r}"
        if kind == 'no_text':
            return None if check['absent'] not in deck.text(slide) else \
                f"slide {slide} still shows {check['absent']!r}"
        if kind == 'markup':
            return None if check['contains'] in deck.markup(slide) else \
                f"slide {slide} markup lacks {check['contains']!r}"
        if kind in ('shape', 'no_shape'):
            element = deck.shapes(slide).get(check['id'])
            if kind == 'no_shape':
                return None if element is None else f"slide {slide} still holds shape {check['id']}"
            if element is None:
                return f"slide {slide} lost shape {check['id']}"
            wanted = check.get('offset')
            if wanted is not None and deck.offset(element) != tuple(wanted):
                return f"shape {check['id']} sits at {deck.offset(element)}, {tuple(wanted)} expected"
            return None
        if kind == 'comment':
            return None if any(check['text'] in text for text in deck.comments(slide)) else \
                f'slide {slide} lost its modern comment'
        if kind == 'timing':
            found, ranges = deck.timing(slide, check['spid'])
            if not found:
                return f"slide {slide} lost the build on shape {check['spid']}"
            wanted = check.get('paragraphs')
            if wanted is not None and tuple(wanted) not in ranges:
                return f"the build targets paragraphs {ranges}, {tuple(wanted)} expected"
            return None
        return f'unknown check {kind!r}'
    except (IndexError, KeyError, ValueError, TypeError, ET.ParseError) as exc:
        return f'{kind}: the save-back does not read: {exc}'


# ---- judging one Office receipt -------------------------------------------

def bound(receipt: dict, sha256: str, status: str) -> str | None:
    """deck_oracle's binding rules: the receipt and its staged copy are this file."""
    if (receipt.get('input') or {}).get('sha256') != sha256:
        return 'the receipt is for other bytes'
    staged = receipt.get('staged_input_sha256')
    if (staged is not None and staged != sha256) or (staged is None and status != 'unsupported'):
        return 'the staged copy is not the candidate'
    return None


def environment_timeout(receipt: dict, status: str) -> str | None:
    """A custody or environment timeout, or one before staging: the environment's, never the deck's."""
    if status == 'timed_out' and (receipt.get('custody_timeout') or receipt.get('staged_input_sha256') is None):
        return f"environment: {receipt.get('detail', '')}"
    return None


def judge(entry: dict, output: Path, office_run: dict | None) -> tuple[str, str, str | None]:
    path = output / 'receipt.json'
    if not path.exists():
        why = 'not run'
        stopped = (office_run or {}).get('stopped') or ''
        if entry['trust'] == 'untrusted' and not (office_run or {}).get('isolated_account'):
            why = 'not run: untrusted candidates open only in the isolated test account'
        elif stopped.startswith('environment'):
            why = f'not run: {stopped}'
        return 'inconclusive', why, None
    receipt = json.loads(path.read_text())
    status = receipt.get('status', 'unsupported')
    # Timeouts are classed before the staged binding: a deck never staged
    # has no staged hash, and that is no byte mismatch.
    if (receipt.get('input') or {}).get('sha256') != entry['sha256']:
        return 'failed', 'the receipt is for other bytes', status
    environment = environment_timeout(receipt, status)
    if environment:
        return 'inconclusive', environment, status
    problem = bound(receipt, entry['sha256'], status)
    if problem:
        return 'failed', problem, status
    mismatch = oracle_mod.environment_mismatch(receipt.get('environment'))
    if mismatch:
        return ('inconclusive' if status in ('unsupported', 'timed_out') else 'failed'), mismatch, status
    if status in ('timed_out', 'unsupported'):
        return 'inconclusive', f"{status}: {receipt.get('detail', '')}", status
    if status != 'clean':
        return 'failed', f"{status}: {receipt.get('detail', '')}", status
    try:
        deck = SaveBack(output / 'reference.pptx')
    except (OSError, KeyError, StopIteration, ValueError, zipfile.BadZipFile, ET.ParseError) as exc:
        return 'failed', f'the save-back does not read: {exc}', status
    failures = [problem for problem in (evaluate(check, deck, receipt) for check in entry['checks']) if problem]
    return ('failed', '; '.join(failures), status) if failures else ('passed', '', status)


def judge_calibration(entry: dict, output: Path) -> tuple[str, str]:
    path = output / 'receipt.json'
    if not path.exists():
        return 'inconclusive', 'not run'
    receipt = json.loads(path.read_text())
    status = receipt.get('status', 'unsupported')
    if (receipt.get('input') or {}).get('sha256') != entry['sha256']:
        return 'failed', 'the receipt is for other bytes'
    environment = environment_timeout(receipt, status)
    if environment:
        return 'inconclusive', environment
    problem = bound(receipt, entry['sha256'], status)
    if problem:
        return 'failed', problem
    mismatch = oracle_mod.environment_mismatch(receipt.get('environment'))
    if mismatch:
        return ('inconclusive' if status in ('unsupported', 'timed_out') else 'failed'), mismatch
    if status == entry['expected_oracle']:
        return 'passed', ''
    if status in ('unsupported', 'timed_out'):
        return 'inconclusive', f"{status}: {receipt.get('detail', '')}"
    return 'failed', f"PowerPoint gave {status}, {entry['expected_oracle']} expected"


# ---- assembling the receipt ------------------------------------------------

def assemble(run: Path, manifest: dict, results: Path) -> int:
    office_path = results / 'office-run.json'
    office_run = json.loads(office_path.read_text()) if office_path.exists() else None
    environment = (office_run or {}).get('environment') or {}
    verdicts = {entry['id']: judge(entry, results / entry['id'], office_run)
                for entry in manifest['candidates']}
    calibration = {entry['id']: judge_calibration(entry, results / 'calibration' / entry['id'])
                   for entry in manifest['calibration']}
    office_steps = {}
    for step in OFFICE_STEPS:
        rows = [(entry['id'], verdicts[entry['id']][:2]) for entry in manifest['candidates']
                if step in entry['steps']]
        if step == REGRESSION:
            rows += [(f'calibration.{case}', verdict) for case, verdict in calibration.items()]
            fonts = (office_run or {}).get('font_versions') or []
            if not fonts or any(line.startswith('font versions unavailable') for line in fonts):
                rows.append(('font versions', ('inconclusive', 'font versions were not recorded')))
        office_steps[step] = aggregate(rows)
    steps = [worst(record['engine'], office_steps[record['step']]) if record['office'] else record['engine']
             for record in manifest['steps']]
    clean = bool(verdicts) and all(status == 'clean' for _, _, status in verdicts.values())
    receipt = {
        'profile': manifest['profile'],
        'powerpoint_version': environment.get('powerpoint', 'unknown'),
        'macos_version': f"{environment.get('macos', 'unknown')} ({environment.get('macos_build', 'unknown')})",
        'font_versions': (office_run or {}).get('font_versions') or [],
        'steps': steps,
        'clean': clean,
    }
    is_open = clean and len(steps) == 8 and all(step == 'passed' for step in steps)
    request = {'receipt': receipt}
    (results / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (results / 'oracle-request.json').write_text(json.dumps(request, indent=2) + '\n')
    evidence = {
        'run': str(run), 'source': manifest.get('source'), 'projector': manifest.get('projector'),
        'profile': manifest['profile'], 'gate_opens': is_open, 'office_run': office_run,
        'engine_steps': [record['engine'] for record in manifest['steps']],
        'office_steps': {str(step): value for step, value in office_steps.items()},
        'candidates': {case: {'verdict': v, 'detail': d, 'status': s} for case, (v, d, s) in verdicts.items()},
        'calibration': {case: {'verdict': v, 'detail': d} for case, (v, d) in calibration.items()},
    }
    (results / 'gate-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    for record, step in zip(manifest['steps'], steps):
        kind, detail = split(step)
        print(f"step {record['step']} {record['name']}: {kind}{(' ' + detail) if detail else ''}")
    print(f"clean={str(clean).lower()} candidates={len(verdicts)} "
          f"ran={sum(1 for _, _, status in verdicts.values() if status)}")
    print('## DECK-GATE-REQUEST ' + json.dumps(request, separators=(',', ':')))
    print(f"## DECK-GATE open={str(is_open).lower()} profile={manifest['profile']} "
          f"projector={manifest.get('projector')} source={manifest.get('source')} "
          f"request={results / 'oracle-request.json'}")
    return 0 if is_open else 1


# ---- the Office pass -------------------------------------------------------

class Stopped(BaseException):
    """A stop signal, raised where the pass is so every finally (the lock's) runs."""


def _stop(signum, _frame):
    raise Stopped(signal.Signals(signum).name)


@contextlib.contextmanager
def signals_held():
    """Hold stop signals while the lock changes hands; a pending one lands after."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, HELD_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


# The owner line of the lock this process took, until it is released.
_held_lock: str | None = None


def take_lock(owner: str) -> None:
    """Take the shared Office lock. The caller releases it in a finally, even
    when this raises after the lock directory was made."""
    global _held_lock
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    line = f'{owner} pid={os.getpid()}\n'
    with signals_held():
        try:
            LOCK.mkdir()
        except FileExistsError:
            holder = (LOCK / 'owner').read_text().strip() if (LOCK / 'owner').exists() else 'unknown'
            raise SystemExit(f'REFUSED: the shared Office lock {LOCK} is held ({holder}); one Office session at a time')
        _held_lock = line
        (LOCK / 'owner').write_text(line)


def release_lock() -> str | None:
    """Release the lock this process took, if it holds one; why it could not, else None. Never raises."""
    global _held_lock
    if _held_lock is None:
        return None
    with signals_held():
        owner = LOCK / 'owner'
        try:
            found = owner.read_text()
        except FileNotFoundError:
            found = None  # stopped before the owner line was written, or removed by hand
        except OSError as exc:
            return f'the lock owner does not read: {exc}'
        if found is not None and found != _held_lock:
            _held_lock = None
            return f'the lock now names another holder ({found.strip()}); left in place'
        try:
            owner.unlink(missing_ok=True)
            LOCK.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            try:
                shutil.rmtree(LOCK)
            except OSError as exc:
                return f'the lock was not removed: {exc}'
        _held_lock = None
    return None


def run_one(candidate: Path, output: Path, observer: str, timeout: int, custody: list[int]) -> str | None:
    """One serial oracle run; the reason to stop the pass, if any. `custody` counts
    the custody queries in a row that timed out."""
    if (output / 'receipt.json').exists():
        print(f'{output.name}: kept from an earlier pass', flush=True)
        return None
    if output.exists():
        shutil.rmtree(output)  # an earlier pass stopped before writing its receipt
    output.parent.mkdir(parents=True, exist_ok=True)
    receipt = oracle_mod.oracle(candidate, output, observer=observer, timeout=timeout)
    print(f"{output.name}: {receipt['status']} - {receipt['detail']}", flush=True)
    if receipt.get('cleanup_warning'):
        return f"cleanup: {receipt['cleanup_warning']}"
    custody[0] = custody[0] + 1 if receipt.get('custody_timeout') else 0
    if custody[0] >= CUSTODY_TIMEOUTS_STOP:
        return (f'environment: PowerPoint left {custody[0]} custody queries in a row unanswered '
                f"({receipt['detail']}); the remaining cases are not run")
    if receipt['status'] == 'unsupported':
        return f"unsupported: {receipt['detail']}"
    return None


def font_families(paths: list[Path]) -> set[str]:
    """Latin typefaces the candidates name (themes and runs; theme references excluded)."""
    faces = set()
    for path in paths:
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if name.endswith('.xml') and (name.startswith('ppt/theme/') or name.startswith('ppt/slides/')):
                        for element in ET.fromstring(archive.read(name)).iter(A + 'latin'):
                            face = element.get('typeface', '')
                            if face and not face.startswith('+'):
                                faces.add(face)
        except (OSError, KeyError, zipfile.BadZipFile, ET.ParseError):
            continue
    return faces


def font_versions(run: Path, manifest: dict, environment: dict) -> list[str]:
    """Canon: PowerPoint, macOS and font versions on every receipt (step 8)."""
    lines = [f"font inventory sha256 {environment.get('font_inventory_sha256')} "
             f"(account {environment.get('font_account')})"]
    families = font_families([run / entry['file'] for entry in manifest['candidates'] if entry['trust'] == 'fixture'])
    try:
        out = subprocess.run(['system_profiler', '-json', 'SPFontsDataType'], capture_output=True,
                             text=True, timeout=900, check=True).stdout
        installed: dict[str, set[str]] = {}
        for font in json.loads(out).get('SPFontsDataType', []):
            for face in font.get('typefaces') or []:
                family = face.get('family') or face.get('_name')
                if family:
                    installed.setdefault(family, set()).add(face.get('version') or 'unversioned')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return lines + [f'font versions unavailable: {exc}']
    for family in sorted(families):
        versions = installed.get(family)
        lines.append(f"{family} {', '.join(sorted(versions))}" if versions else f'{family} not installed')
    return lines


def cmd_office(args) -> int:
    run = args.run.resolve()
    manifest = load_run(run)
    problems = verify(run, manifest)
    if problems:
        print('REFUSED: the run directory does not match its manifest', file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        return 2
    if sys.platform != 'darwin' or not oracle_mod.APP.exists():
        print('REFUSED: PowerPoint for Mac is not installed here; the Office half runs on the Mac mini', file=sys.stderr)
        return 2
    office = manifest['office']
    observer = args.observer or office['observer']
    timeout = args.timeout or office['timeout_seconds']
    user = getpass.getuser()
    if args.isolated_account and user in office['owner_accounts']:
        print(f'REFUSED: {user} is an owner account; untrusted decks open only in the isolated test account', file=sys.stderr)
        return 2
    # The approved pin's locale is empty, as the recorded Mac mini runs were.
    for name in list(os.environ):
        if name == 'LANG' or name.startswith('LC_'):
            del os.environ[name]
    reason = oracle_mod.observer_status(observer)
    environment = oracle_mod.env_pin(observer) if not reason else None
    reason = reason or oracle_mod.environment_mismatch(environment)
    if reason:
        print(f'REFUSED: {reason}', file=sys.stderr)
        return 2
    if oracle_mod.app_pid() and oracle_mod.presentations():
        print('REFUSED: PowerPoint has open presentations; close them first, never ours to close', file=sys.stderr)
        return 2
    results = (args.results or run / 'office-results').resolve()
    results.mkdir(parents=True, exist_ok=True)
    account, inventory, rows = oracle_mod.font_inventory()
    (results / 'font-inventory.json').write_text(json.dumps(
        {'font_account': account, 'font_inventory_sha256': inventory, 'rows': list(rows)}, indent=2) + '\n')
    stopped = quit_error = lock_error = None
    started = time.time()
    custody = [0]
    # SIGTERM and SIGHUP unwind through the finally below, as SIGINT does.
    previous = {sig: signal.signal(sig, _stop) for sig in STOP_SIGNALS}
    try:
        take_lock(f'deck-gate {manifest.get("source")} {run}')
        already_running = oracle_mod.app_pid() is not None
        try:
            for entry in manifest['candidates']:
                if entry['trust'] == 'untrusted' and not args.isolated_account:
                    continue
                stopped = run_one(run / entry['file'], results / entry['id'], observer, timeout, custody)
                if stopped:
                    break
            for entry in [] if stopped else manifest['calibration']:
                stopped = run_one(run / entry['file'], results / 'calibration' / entry['id'], observer,
                                  entry['timeout_seconds'], custody)
                if stopped:
                    break
        finally:
            if not already_running:
                try:
                    oracle_mod.quit_if_empty()
                except (RuntimeError, subprocess.TimeoutExpired) as exc:
                    quit_error = str(exc)
    except Stopped as exc:
        stopped = f'stopped by {exc}'
    finally:
        try:
            lock_error = release_lock()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    uncertain = bool(stopped and stopped.startswith('cleanup')) or quit_error is not None
    if uncertain:
        # Never closed here: the next pass refuses while PowerPoint holds a presentation.
        print(f'PowerPoint custody is uncertain ({stopped or quit_error}); check the Mac mini '
              'before the next pass', file=sys.stderr)
    if lock_error:
        print(f'LOCK NOT RELEASED at {LOCK}: {lock_error}; remove it by hand', file=sys.stderr)
    office_run = {
        'environment': environment, 'user': user, 'isolated_account': bool(args.isolated_account),
        'observer': observer, 'timeout_seconds': timeout, 'started_at': started,
        'finished_at': time.time(), 'stopped': stopped, 'quit_error': quit_error,
        'custody_uncertain': uncertain, 'lock_retained': lock_error is not None, 'lock_error': lock_error,
        'font_versions': font_versions(run, manifest, environment),
    }
    (results / 'office-run.json').write_text(json.dumps(office_run, indent=2) + '\n')
    if stopped:
        print(f'STOPPED: {stopped}', file=sys.stderr)
    return assemble(run, manifest, results)


def cmd_assemble(args) -> int:
    run = args.run.resolve()
    manifest = load_run(run)
    problems = verify(run, manifest)
    if problems:
        print('REFUSED: the run directory does not match its manifest', file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        return 2
    return assemble(run, manifest, (args.results or run / 'office-results').resolve())


def cmd_plan(args) -> int:
    run = args.run.resolve()
    manifest = load_run(run)
    problems = verify(run, manifest)
    print(f"run {run}: profile {manifest.get('profile')}, projector {manifest.get('projector')}, "
          f"source {manifest.get('source')}")
    for record in manifest.get('steps', []):
        kind, detail = split(record['engine'])
        office = ' (+ the Office half)' if record['office'] else ''
        print(f"step {record['step']} {record['name']}: engine {kind}{(' ' + detail) if detail else ''}{office}")
    fixture = [entry for entry in manifest['candidates'] if entry['trust'] == 'fixture']
    untrusted = [entry for entry in manifest['candidates'] if entry['trust'] == 'untrusted']
    timeout = manifest['office']['timeout_seconds']
    print(f"{len(fixture)} fixture candidates, {len(untrusted)} untrusted candidates (isolated account only), "
          f"{len(manifest['calibration'])} calibration fixtures; at most "
          f"{(len(fixture) + len(untrusted) + len(manifest['calibration'])) * timeout // 60} min of PowerPoint "
          f"at {timeout} s each")
    for problem in problems:
        print(f'PROBLEM {problem}')
    return 1 if problems else 0


def cmd_acquire(args) -> int:
    repo, corpus = args.repo.resolve(), args.corpus.resolve()
    spec = json.loads((repo / CASE_MANIFEST).read_text())['regression']['pptarena']
    arena = json.loads((repo / spec['manifest']).read_text())
    excluded = {rule['id'] for rule in spec.get('exclude', [])}
    cases = [case for case in arena['cases']
             if (spec['select'] == 'all' or case['id'] in spec.get('cases', [])) and case['id'] not in excluded]
    corpus.mkdir(parents=True, exist_ok=True)
    failures = 0
    for case in cases:
        destination = corpus / case['id']
        original = destination / 'original.pptx'
        if original.is_file() and oracle_mod.digest(original) == case['original']['sha256']:
            print(f"{case['id']}: kept", flush=True)
            continue
        if destination.exists():
            shutil.rmtree(destination)
        try:
            oracle_mod.acquire(case['id'], destination)
            print(f"{case['id']}: acquired", flush=True)
        except Exception as exc:  # one failed pair leaves its case inconclusive, not the run
            failures += 1
            print(f"{case['id']}: FAILED {exc}", file=sys.stderr, flush=True)
    print(f'{len(cases) - failures} of {len(cases)} PPTArena originals ready in {corpus}')
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    acquire = sub.add_parser('acquire', help='fetch the selected PPTArena originals (never opens them)')
    acquire.add_argument('repo', type=Path, help='repository root holding scripts/office/pptx-live-v1.json')
    acquire.add_argument('corpus', type=Path, help='corpus directory: <corpus>/<case>/original.pptx')
    plan = sub.add_parser('plan', help='verify a run directory; no Office')
    plan.add_argument('run', type=Path)
    for name, helptext in (('office', 'Mac mini only: open every candidate serially, then assemble'),
                           ('assemble', 'join the Office results to the engine outcomes; no Office')):
        command = sub.add_parser(name, help=helptext)
        command.add_argument('run', type=Path)
        command.add_argument('--results', type=Path, help='Office results (default: RUN/office-results)')
        if name == 'office':
            command.add_argument('--isolated-account', action='store_true',
                                 help='this is the isolated test account: also open untrusted candidates')
            command.add_argument('--observer', choices=('cua', 'system-events'))
            command.add_argument('--timeout', type=int, help='seconds per candidate (default: the run manifest)')
    args = parser.parse_args()
    return {'acquire': cmd_acquire, 'plan': cmd_plan, 'office': cmd_office,
            'assemble': cmd_assemble}[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
