# Run-bound repository conflict proposals

`self.code.proposal_resolve` proposes one whole-file resolution of a typed
repository conflict. It does not approve, enqueue or land the proposal.

The input contains the same `work`, `path`, `content`, `message` and optional
`declaration` fields as `self.code.proposal_submit`, plus:

- `branch_subject`: the branch entity that holds the conflict.
- `conflict`: the open typed conflict claim.
- `branch`: the recorded branch name.

The output is `RepoProposalSubmitOutput`, including the proposal, work, path,
pinned base, session, provenance and declaration. The caller can submit the
proposal to the existing merge-queue door after its normal review.

The executor supplies the real actor, live lease, TASK and read lane. The
proposal uses the run's own work and current declaration. The existing Grant,
pinned-base, writer admission, provenance and native conflict checks still
apply. No owner authority is fabricated and the owner resolution doors are
unchanged. A missing host model-request witness retains the existing
`repo_provenance_required` answer.

The host records the actual `self.code.proposal_resolve` effect and
`self.code.proposal_resolve.v1` derivation in the provenance claim. Ordinary
submit provenance remains `self.code.proposal_submit.v1`.

On landing, this uses the existing typed `ResolveConflictFile` operation.
Each file contributes its resolution claim. The existing native writer closes
the open conflict only after the retained active resolution claims cover all
conflicted paths, and links every contributing per-file receipt. One file does
not claim to resolve the other paths. Automatic overlap-handoff selection and
resolution records for ordinary combined proposals remain separate queue
behavior; this door does not replace those proposals or add a typed-only gate.
