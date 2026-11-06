# Trusted policy-value narrowing

Trusted policy manifests that are neither seeded nor authored only narrow policy
values. For each numeric or posture key and scope, an authored row replaces the
shipped fallback. Other trusted rows meet that baseline using the key's existing
order: some keys take a minimum, others a maximum, and opt-out posture uses its
existing restrictive composition. A looser row cannot widen the selected value.

When a narrowing row changes the value, its actual row reference and explanation
identify the deciding row. Equal values keep the selected baseline's provenance.
An authored baseline keeps its parent-override setting; a narrowing row cannot
create that permission. Without an authored baseline, a narrowing row does not
release a parent bound.

Distinct authored rows for one key and scope still conflict. Distinct seeded
fallbacks also still conflict. Narrowing does not hide either error. Stored rows
at a scope their key does not admit retain the existing malformed-manifest result.

`scope_precedence` has no defined meet. This change leaves its existing selection
and conflicting-row behavior unchanged; it does not invent an order for that key.

This is a manifest-fold change, not a format change. Stored manifest bytes,
trusted-origin checks, authored-holder proofs and the ordinary Gate remain intact.
