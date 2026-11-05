# Merge a local claim refinement

These owner routes connect an existing session-branch claim edit to the native
approve-once merge and the server's typed decision host. The host needs its
configured decision seats. They do not submit a new edit or reserve held-out
labels; those remain the existing native operations.

## Read the edit and its ruling

```sh
oneiron api raw GET /v1/owner/claims/refinements/CANDIDATE
```

`CANDIDATE` is the stored refinement's 32-hex entity id. The reply contains
`refinement`, the native local branch record, and `receipt`, the stored merge
ruling or `null`. A missing or erased refinement returns not found.

## Approve and run its merge

```sh
oneiron api raw POST /v1/owner/claims/refinements/CANDIDATE/approve \
  --data '{"question":"Is this edit useful upstream?","question_version":1}'
```

The question text and its version are the owner's configuration, not a server
prompt or default. The native prepare step binds them to this candidate and its
actual base, resident and owner-held labels. The request cannot replace the
resident, claim body, held-out labels, acceptance result or clock.

The live owner of this vault approves the prepared effect once. The same vault's
`DecisionHost::merge_claim_refinement` then runs the existing usefulness and
held-out replay decisions outside the writer, under their existing shared
60-second budget. Approval alone does not accept the edit.

The reply contains the actual consent decision and an `outcome` of `admitted`,
`refused` or `pending_consent`. A ruled merge includes its native `receipt`;
`pending_consent` has no merge receipt. Native errors are returned unchanged.
A settled or erased candidate keeps the native refusal on another approve;
read its stored result through GET rather than treating another question as a
new evaluation. A model failure is not a merge ruling.

Both routes use the ordinary owner credential. Approval revalidates that same
owner in the native applying transaction. The routes do not grant an agent
owner authority, bypass the merge's native checks or change its model budget.
