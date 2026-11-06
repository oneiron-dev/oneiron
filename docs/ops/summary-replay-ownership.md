# Summary replay response ownership

A summary reader job saves its text in the job's own replay record. The save
uses the existing owned replay API with:

- content run: `job.run`, which owns the summary output;
- actor: `job.binding.actor.entity`, the actor captured when the parent
  spawned the job.

The parent run remains the job's ancestry. It is not substituted for the
summary's own content run. No actor is guessed from a run id or model, and
no new owner field or table is introduced.

The owned save publishes the native response-owner descriptor in the same
transaction as the replay row. Once published, that descriptor lets the
existing actor erase find the summary replay row and its stored-result body
occurrences. Existing first-owner and erased-owner rules remain unchanged.
Canonical and on-record session saves use the native owned-save route;
off-record overlay saves retain the existing no-base-owner behavior.

Active generation, source admission, member taint, output path/handle,
`summary` binding, finding report, memo and completion behavior are unchanged.
No format, default, limit, or permission changes are needed.

## Remaining first-publication case

The native owned-save implementation currently runs the replay erase fence
before its first owner stamp. A first summary save **after** its spawning
actor was erased therefore needs a separate ordering repair. This caller fix
does not claim to close that case or all summary erasure paths. The residual
is recorded as FIX 13432; historical FIX 9710 remains partial.
