# Runtime-hook proposal recovery

A saved `Propose` intent uses a deterministic claim identity derived from its
hook run key. The intent may still be pending after its claim has committed,
for example if the process exits before recording the intent's outcome.

Recovery must not write `Proposed` over an owner decision made in that window.
The hook-only claim door first runs the existing claim resolution and writer
admission. It then reads the current claim in the same actor-content writer.
An active, exact replay with no competing prior head can return the existing
claim without another candidate put or Gate decision.

The replay check compares the belief fields and the complete write-envelope
evidence, including the author, actor class, binding and run key. It also
requires the original absent salience and session tag. A matching identity
alone is not enough. The current shared-vault authority for the existing claim
is checked again before returning it.

No support rows are staged on this path. Actor-content finalization still
checks that support obligations are empty and the writer binding is unchanged.
The normal receipt reads the persisted approval and latest decision; it does
not claim a new owner approval, Gate execution or decision timestamp. Row
clocks, stale state and stored decay annotations are left untouched.

Ordinary `claim_propose`, commit and upsert calls do not opt into this path.
First proposals, changed content or stamps, non-active rows, hard-delete cases,
competing prior heads and the special commitment/public-booking support paths
keep their existing admission and gated-write behavior. This is not a claim
that every changed or erased hook-intent recovery case is idempotent.

There is no new setting, default, retention rule or stored format. Deploy the
engine containing the change; no SDK, QuickJS artifact or migration is needed.
