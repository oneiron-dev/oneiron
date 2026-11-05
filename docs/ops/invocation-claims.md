# Named invocation replies and hook asks

A client-named invocation wraps one call. A completed JSON reply is kept
under the existing invocation claim rules, so a duplicate can read the same
outcome without running the effect again.

A hook that asks before running is different from an accepted asynchronous
job. The facade identifies that pause by HTTP 202 together with either the
native `PENDING_ASK` error code (`MEMORY_CODE_PENDING_ASK`) or an error's
native `VerbHookStop::Pending` payload. Chat keeps its existing
`verb_hook_pending` code and carries that typed stop. A status alone is not
enough. The same classifier is used by invocation completion, facade error
replay, and the in-process action row door.

For that pending-ask reply, completion releases the durable invocation
intent through the existing failure path. Requests already waiting on the
live call still receive its original pending reply. A later retry with the
same invocation can reach the native hook boundary again; it is not trapped
replaying a cached pause after the ask settles. The hook still owns its ask,
resume, authority and once-only effect rules.

A genuine asynchronous HTTP 202 answer without that native error code or
pending-stop payload remains a successful reply. It is retained by the
existing durable claim policy and returned as a successful action-row
answer. Other status rules, claim identity, conflict checks, restart
handling, retention, erase and replay release checks are unchanged.

A storage failure while finishing is still logged and does not pretend the
intent was released. This change adds no ask-state polling, new expiry,
retry timer, migration, or alternate invocation id.
