"""PowerPoint session housekeeping for the OF-510 deck gate's Office half.

Three jobs deck_gate.py and deck_oracle.py hand over (gate observer, FIX 8296,
8297):

- PowerPoint's windows, read by index and read again when one closes under
  the observer or it fails, within the candidate's deadline: an observer
  error is never taken as the deck's, and never stops a pass;
- the named first-run dialogs a candidate session dismisses. Each is dismissed
  at most once per Office pass, wherever a candidate's session meets it (its
  setup, its observation, its cleanup), and every dismissal is a record. A
  dialog not named here keeps the oracle's rule: unsupported, never a pass;
- the shared Office lock a dead run left behind, moved aside (never deleted)
  only when the process its owner line names is provably gone.

Beside deck_gate.py in the repo and in a run directory; no engine imports.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent

# PowerPoint's first-run notices: a name for the record, the dialog title or
# text that identifies it (compared case-insensitively, a typographic
# apostrophe read as a plain one), and the buttons that close it without
# accepting anything, in the order tried. When none is found the window's own
# close button is used; nothing else is ever clicked.
KNOWN_DIALOGS = (
    ('copilot-introduction', ('introducing copilot',),
     ('Close', 'Not Now', 'Maybe Later', 'Got It', 'Skip', 'No Thanks')),
    ('whats-new', ("what's new", "what's new in powerpoint"), ('Close', 'Got It', 'Skip')),
)
# Seconds one dismissal's System Events call may take.
DISMISS_SECONDS = 8


def _plain(text: str) -> str:
    return text.replace('’', "'").replace('‘', "'").strip().lower()


class FirstRun:
    """The known first-run dialogs met in one Office pass, each dismissed once.

    Call it with a System Events observation (`DIALOG:<text>` entries) and
    where the session is; it dismisses the named dialogs it has not tried
    yet and returns the records it made now. `records` keeps them all."""

    def __init__(self, log=print):
        self.tried: set[str] = set()
        self.records: list[dict] = []
        self.log = log

    def __call__(self, observed: list[str], where: str) -> list[dict]:
        made = []
        for name, texts, buttons in KNOWN_DIALOGS:
            if name in self.tried:
                continue
            seen = next((entry.partition(':')[2] for entry in observed
                         if entry.startswith('DIALOG:') and _plain(entry.partition(':')[2]) in texts), None)
            if seen is None:
                continue
            self.tried.add(name)
            try:
                result = subprocess.run(['osascript', str(ROOT / 'powerpoint_dismiss.applescript'), seen, *buttons],
                                        capture_output=True, text=True, timeout=DISMISS_SECONDS, check=False)
                outcome = (result.stdout.strip() if result.returncode == 0
                           else f'not dismissed: osascript exit {result.returncode}: {result.stderr.strip()}')
            except (OSError, subprocess.TimeoutExpired) as exc:
                outcome = f'not dismissed: {exc}'
            record = {'dialog': name, 'text': seen, 'where': where, 'at': time.time(), 'result': outcome}
            self.records.append(record)
            made.append(record)
            self.log(f'first-run dialog {name!r} ({seen!r}) at {where}: {outcome}', flush=True)
        return made


# ---- observing PowerPoint's windows -------------------------------------------

# A window closed while powerpoint_windows.applescript read it.
TORN = 'VANISHED:'
# Seconds one observer call may take; also a cleanup observation's budget.
OBSERVER_SECONDS = 5


class ObserverTorn(RuntimeError):
    """A PowerPoint window closed while the observer read it: read again."""


def _osascript(args: list[str], timeout: float) -> str:
    r = subprocess.run(['osascript', *args], capture_output=True, text=True, timeout=timeout, check=False)
    if r.returncode:
        raise RuntimeError(f'osascript exit {r.returncode}: {r.stderr.strip()}')
    return r.stdout.strip()


def windows(observer: str, pid: int, timeout: float | None = None) -> list[str]:
    """PowerPoint's windows as `WINDOW:<title>` and `DIALOG:<text>` entries."""
    budget = min(OBSERVER_SECONDS, timeout) if timeout is not None else OBSERVER_SECONDS
    if observer == 'cua':
        r = subprocess.run(['cua-driver', 'call', 'list_windows', json.dumps({'pid': pid})],
                           capture_output=True, text=True, timeout=min(6, timeout) if timeout else 6, check=False)
        if r.returncode:
            raise RuntimeError(f'cua-driver exit {r.returncode}: {r.stderr.strip()}')
        return ['WINDOW:' + w['title'] for w in json.loads(r.stdout)['windows'] if w.get('title')]
    text = _osascript([str(ROOT / 'powerpoint_windows.applescript')], budget)
    entries = [entry.strip() for entry in text.split('\x1e') if entry.strip()]
    if TORN in entries:
        raise ObserverTorn('a PowerPoint window closed while the observer read it')
    return entries


def observe(observer: str, pid: int, deadline: float, dialogs=None, where: str = '') -> list[str]:
    """`windows`, read again until `deadline` while a window closes under the
    observer or it fails, and after `dialogs` dismissed a known first-run
    dialog; the observer's last error once the deadline passes."""
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            observed = windows(observer, pid, deadline - time.monotonic())
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            last = exc
        else:
            if not (dialogs and dialogs(observed, where)):
                return observed
            continue
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise last if last is not None else subprocess.TimeoutExpired('osascript', 0)


def expired_detail(action: str, unread: Exception | None, when: str = '') -> str:
    """A deadline's detail, naming the observer error it kept retrying, if any."""
    return f'{action} exceeded deadline{when}' + (f'; the observer kept failing: {unread}' if unread else '')


# ---- the shared Office lock ---------------------------------------------------

LOCK = Path.home() / 'w7-oracle' / 'lock'
# Signals held while the lock changes hands.
HELD_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


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


def take_lock(owner: str) -> str | None:
    """Take the shared Office lock; a lock whose recorded holder is provably
    gone is first moved aside (FIX 8297), and the move's log line returned.
    The caller releases it in a finally, even when this raises after the lock
    directory was made."""
    global _held_lock
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    line = f'{owner} pid={os.getpid()}\n'
    moved = None
    with signals_held():
        try:
            LOCK.mkdir()
        except FileExistsError:
            moved = move_stale_lock(LOCK)
            try:
                if moved is None:
                    raise FileExistsError
                print(moved, flush=True)
                LOCK.mkdir()
            except FileExistsError:
                holder = (LOCK / 'owner').read_text().strip() if (LOCK / 'owner').exists() else 'unknown'
                raise SystemExit(f'REFUSED: the shared Office lock {LOCK} is held ({holder}); one Office '
                                 'session at a time') from None
        _held_lock = line
        (LOCK / 'owner').write_text(line)
    return moved


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


PID = re.compile(r'\spid=(\d+)$')


def holder_gone(owner_line: str) -> int | None:
    """The pid the owner line records, when no such process exists; else None.

    A missing or unreadable pid, a live process, or one of another user's
    (PermissionError) proves nothing: the lock stays."""
    found = PID.search(owner_line.strip())
    if not found:
        return None
    pid = int(found.group(1))
    if pid <= 0 or pid == os.getpid():
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return pid
    except OSError:
        return None
    return None


def run_label(owner_line: str) -> str:
    """The run directory a deck-gate owner line names, as a file-name label."""
    for token in reversed(owner_line.split()):
        if '/' in token:
            label = re.sub(r'[^A-Za-z0-9._-]', '-', Path(token).name)
            if label.strip('.-'):
                return label
    return 'unknown-run'


def move_stale_lock(lock: Path) -> str | None:
    """Move `lock` aside as `<lock>.stale-<run>` when its recorded holder is
    provably gone; the log line, or None when the lock stays where it is.
    The lock is never deleted. A lock another pass took between the read and
    the move goes back."""
    try:
        found = (lock / 'owner').read_text()
    except OSError:
        return None
    pid = holder_gone(found)
    if pid is None:
        return None
    base = f'{lock.name}.stale-{run_label(found)}'
    aside, n = lock.with_name(base), 1
    while aside.exists():
        n += 1
        aside = lock.with_name(f'{base}-{n}')
    try:
        os.rename(lock, aside)
    except OSError:
        return None
    try:
        moved = (aside / 'owner').read_text()
    except OSError:
        moved = None
    if moved != found:
        try:
            os.rename(aside, lock)
        except OSError:
            return f'moved {lock} to {aside}, then found a different holder in it ({moved!r}); put it back by hand'
        return None
    return f'moved the stale Office lock {lock} aside to {aside}: its holder pid {pid} is gone ({found.strip()})'
