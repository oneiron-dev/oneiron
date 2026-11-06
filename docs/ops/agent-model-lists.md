# Per-agent model lists on code-mode calls

An agent's `models` list names engine model ids, not provider wire names.
A reader, summary or scoped child inherits the frozen list of the run that
spawned it. An empty list keeps the existing house-routed behavior.
`compaction_model` is separate and need not appear in that list.

With the served code-mode backend, the frozen list follows resident steps,
planned-run steps, pattern launches and the reader's own metered backend.
Resident entries use the definition frozen for that dispatch, not a fresh
agent-definition lookup. An unscoped entry gets a copy of its actual ordinary
backend with only the model list changed; scoped and planned entries retain
their existing guards, payers and live leases.

The backend checks the model selected by role
admission, not only the configured model checked before that admission. An
off-list selected model follows the existing admission-denied path; the
server log records the list check's reason.

A permitted call keeps every listed rung and every eligible owner fallback
that is also listed. Filtering is call-local: it does not change shared
routes, cooldowns, meters or owner fallback settings. Rung order and the
original receipt positions are retained. An off-list fallback cannot be
sent; another eligible listed fallback can still answer. No exact-model-only
shortcut replaces the normal walk.

This covers the served backends carrying the actual frozen list. MCP
`execute_code`, off-record own steps and other paths without that carrier
retain their existing routing. Injected or custom providers and the planner's
own model calls are not covered by a claim that they cannot substitute models.
The pattern funding probe remains a probe, not a list refusal. The live
compaction admission remains separate; this check does not constrain its
explicitly independent model.

## Project-aware fresh task seats

A resident agent dispatch carries its frozen project, target agent definition
and original task-type stamp into a fresh seat's model-pick state and its
description-route grades. Each eligible model's `learned` entry contains the
planner's scoped reliability mean, own runs and total estimate weight. Thin
project leaves borrow the vault tree's measured outcomes through the same
native donor blend as planning, without counting them as own runs.

These values inform the existing judge; they do not filter models, set an
effort rung or confer authority. A failed donor read leaves the primary
measurements in place. Unavailable primary evidence is logged and omitted,
not reported as a zero measurement. The original type stamp is read against
its kept tree, not placed again. A missing kept tree adds no evidence.

The context is not serialized into the durable task pin. Existing pins,
warm-seat reuse, planned-model overrides and admission rules keep their
current behavior. Generic code runs, reader children and turn programs have
no qualified project carrier here and keep their unprojected state. The
native routed-verdict request door accepts this context, but its existing
verdict caller still supplies none; no project-aware verdict caller is
claimed.

## Launch USD estimates

An agent launch with a resolved plan prices that exact engine model. Without
one, the quote uses the vault manifest's role binding in the launch statement's
own read transaction. A missing model row or unreadable binding stays unknown;
it never falls back to another model's price.

When that transaction has no manifest, an unregistered role-seat id can be
priced through the same runtime seat only if all its rungs and every possible
owner-selectable fallback use one distinct engine model. Repeated offers for
that same model are allowed. The fallback inventory uses the existing wire and
on-device rules, not today's health, rest state or selected fallback. Multiple
possible models stay unknown rather than pricing only the first or cheapest.
An explicit manifest pin, including a literal seat id, is never normalized this
way. A changed runtime seat does not relabel an older quote's seat id.

The estimate still needs that engine's catalog USD rate, or an explicitly free
catalog price. Non-token units also need the exact serving offer's native-unit
rate. Missing or ambiguous prices stay unknown, never zero. This changes only
the quote: it does not choose a model, restrict a fallback, or change admission.
