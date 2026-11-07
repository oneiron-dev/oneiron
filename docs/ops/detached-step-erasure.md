# Detached step waits during erase

A detached SDK step stores a device-local binding of its actor, subject and step
hash. The actor-field erase sweep now reaches that binding through the existing
side-table scrub catalog. The accepted erase and the scrub use the same writer.

Erasing either the actor or subject removes that detached binding. The scrub also
removes private step-only trap bindings for the same attempt and original step
hash. It checks the native step-only owner token; attempt-parking bindings and
other attempts are unchanged. This removes erased waits from the local open-wait
inventory and revokes their local consume authority.

Retirement does not read a claim that the erase may already have removed. It does
not signal a wait, return an answer, or append a `Sent` or `Consumed` transition.
The ordinary claim erase keeps its own behavior. Normal waits, attempt queues,
leases, budgets and checkpoints use their existing paths. Table prefixes, value
layouts and restore classes are unchanged.
