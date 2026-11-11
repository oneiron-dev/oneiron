# Canonical wait resume retirement

A canonical code run commits its resumed replay record and retires that wait
generation's waiter, delivery and trap rows in one existing replay transaction.
This covers ordinary entry, same-loop re-entry and pinned program entry: all
three use `resume_delivered_wait` and `put_code_run_wait_resume_record`.

Retirement runs after the holder and delivery erase checks, consent consumption
and any observed-change cursor update. A failed generation check or transaction
aborts both the record and retirement. The waiter is deleted only when its stored
generation matches; delivery and trap keys name the exact run, wait and generation.
Settled replies, observed-change cursors and holder records remain intact.

This removes the crash window between a durable canonical resume and separate
cleanup. It does not change body publication, consent evidence or replay ownership.
Hook cleanup and the public wait-delivery clear operation keep their existing behavior.

Session runs still commit through their captured route. The separate
[Session base wait retirement](session-base-wait-retirement.md) change validates
composed Base reads and retires the changed replay and wait keys after the base
commit. Overlay-route runs stage their cleanup in the same replay transaction
segment before the resume writer returns its generation. Neither change provides
general session restart durability.

No storage format, operating constant, default, cap or deployment artifact changes.
An ordinary engine/server update is sufficient.
