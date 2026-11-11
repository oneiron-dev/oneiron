# Canonical turn-hook waits

A pending `host.turn.generate` hook parks the run before a model step exists.
Retrying the turn resumes its saved hook chain, not a completed step's wait.

When that chain consumes the answered ask, the same canonical write retires
that run's waiter, delivery and trap-index rows for the ask's current wait
generation. This also happens when a later hook in the chain asks again.
Other runs waiting on the same ask and its settled reply remain intact.

Off-record room hooks keep their existing in-memory continuation and routed
wait handling. Ordinary step waits still retire after their resume record
commits.
