# Session-open hook asks

The running driver keeps an app-open hint that `host.session.open` parks on an ask.
It retains the same actor/machine key, sitting id, and resolved hint timestamp.
First settlement of the ask wakes a content-free post-commit signal. Re-enabling
hooks also wakes retained opens, after the switch commits and its binding cache
is invalidated. The driver then retries the ordinary hook boundary; the signal
itself is neither an answer nor authority.
The existing ask deadline also wakes the driver, including while passes are paused
or no other session has an expiry timer.

A tracked app-open reports `SessionHintEffect::OpenPending(ask)` when it is kept
but no sitting was minted. A later tracked open for that key can report the same
blocking ask. These are not successful mint receipts. A completed open still
reports its actual `Minted` or `Bumped` effect.

Later lifecycle hints for the same actor/machine key wait behind the open, in their
original order. Other keys continue to apply hints and close due sittings. Storage
errors retain their existing retry/backoff behavior; an ordinary unanswered ask
does not enter that global retry head. Terminal hook refusals still open nothing.

Retention is in the running driver, not a new durable host continuation. Stopping
that driver drops its in-memory retained hints, just as it drops queued hints.
Calendar transcript imports still use their existing mint-and-close transaction;
this change does not add session hooks to that import path.
