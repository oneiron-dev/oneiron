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

Conflict validation uses an attached repository's physical branch. A detached
source can use its frozen `refs/heads/*` import branch only after the engine
proves the same object store and its exact registered, engine-derived queue
source root. A tag import or another detached worktree supplies no logical
branch.

The host records the actual `self.code.proposal_resolve` effect and
`self.code.proposal_resolve.v1` derivation in the provenance claim. Ordinary
submit provenance remains `self.code.proposal_submit.v1`.

On landing, this uses the existing typed `ResolveConflictFile` operation.
Each file contributes its resolution claim. The existing native writer closes
the open conflict only after the retained active resolution claims cover all
conflicted paths, and links every contributing per-file receipt. One file does
not claim to resolve the other paths. This door does not replace ordinary
combined proposals or add a typed-only gate.

An automatic overlap handoff links only a reconciliation TASK's proposal that
actually covers a conflicted path. It keeps the source batches until the
historically accepted GREEN batches cover every conflicted path. Several
per-file batches can contribute; unrelated TASK output and an unlanded tail do
not complete the handoff. Ordinary `CommitFile`, `CommitFiles` and `ReceivedFiles`
proposals remain eligible alongside typed resolutions.

The queue reads each batch's original slow verdict and stored input receipt to
recover its accepted landed mask, tree and commit. A later GREEN or a changed
reviewed stack does not replace that evidence. Ordinary queue resolutions feed
the same native resolution-claim writer and aggregate closer. Repeating a batch
reuses its recorded contribution; a typed claim already closed during landing
does not make the queue forget its reconciliation.
