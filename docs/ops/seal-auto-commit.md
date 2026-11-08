# Automatic native seal commits

A completed e-sign ceremony does not ask for another approval to keep its verified seal.
The native producer writes a new immutable artifact version with `seal_job` provenance and
its actual `esign.seal:<attempt>` job reference. Signature-image capability uploads remain
Proposed, and ordinary agent-generated versions keep their existing approval behavior.

The shipped manifest names one derived System seal actor, not the shared capability-upload
actor. Its actor-bound Generated source-trust row retains the existing unstamped sensitivity
floor, receipts and warnings, and selects `auto_checker: "native.esign.seal"`. The independent
top-level host/Dreamer `auto_checker` setting is unchanged.

The seal actor is also registered in the engine's native MACHINE provision list.
At host open, the existing host-rooted provisioner enrolls its per-vault key and
retains the signer before seal versions append. Reopening retains that same native
signer, and host re-rooting includes the same actor list. A revoked or foreign
binding still supplies no signer. Mandatory MACHINE claim verification is unchanged.

The producer retains the independent sealer verification, profile coherence and SHA-256 checks.
Only their typed verified outputs can form the private job guard. In the final writer, the
selected native policy checker binds the current attempt lease owner and count, unchanged
document snapshot, actual seal writer and job, and the complete output-target set. Each
version append checks its exact target, BLAKE3 content hash and fresh root-version shape.
A label or derived actor alone cannot earn Auto. Missing or conflicting native checker
selection supplies no seal permit; it never skips consultation.

The ordinary actor, source-trust, privacy and content-write gates still judge the real append.
The same transaction writes all versions, the manifest, per-item profile evidence and terminal
audit, then completes the attempt. Its write envelope stamps the selected checker, policy
frontier, document, snapshot and actual output target. There is no second approval, global
Generated permit, migration, old-format reader or new numeric cap.

Rollout needs matching engine/server and regenerated public policy clients. No organ wire
or sealing algorithm changes here. This source change does not prove a runtime seal, the
full e-sign resource budget, or deployment readiness.
