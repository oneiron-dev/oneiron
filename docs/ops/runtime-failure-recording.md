# Recorded code-run failures

The recording JS host keeps an `AgentsSpawn` dispatch error as a typed `Failed`
bridge-call outcome. The row keeps the original error text, effect and resolved
spawn seats, just as the existing recorded write and speech effects do.

The current step still ends on the original hard failure. Later calls do not
cross that barrier. A resumed run can read the recorded failure rather than see
an unexplained infrastructure gap. This does not retry a spawn, change its
admission, or turn its failure into success.

Gate denials, provider outages and explicit refusals keep their existing
classification. Other effects keep their existing infrastructure-gap behavior.
