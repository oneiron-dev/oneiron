# Training runs cancel

`POST /v1/owner/coach/training-runs/cancel` cancels a staged trained embedder
swap while its binding still waits or fills. Body `{run}` names the training
run id as 32 hex. The reply is the run's `PendingEmbedderBinding`, the same
shape as the run view's `staged`.

`vault.coach.training_runs.cancel` is the same door over the verb table. Input
`{run}` names the run id. The reply is the same binding.

A cancel writes `NotApplied{Cancelled}` in the same owner write. It is not a
retry: `move_abandon` returns a filling move to waiting for the next pass.
It is not an applied undo: `move_undo` undoes an applied swap and resets the
training role. An applied embedder swap keeps the existing undo door.

No new policy, cap, timeout, entity, table, error class, authority, loader,
runtime availability or feature closure is added.
