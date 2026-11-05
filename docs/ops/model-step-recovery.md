# Durable model-step recovery

`ai.steps.submit` checks the actual owner's saved step before it admits a
provider. A saved terminal, including a budget trap still waiting for its
answer, keeps the existing receipt path. The owner can also resume unfinished
work whose response was already saved at `ResponseReceived` or `Logged`, or
whose terminal claim was written before its submission receipt was committed.
Removing the configured model does not make that saved work need a new call.

Recovery matches the same owner's step key and frozen request/retry policy.
The comparison excludes only the host admission fields already bound in the
saved request, including the host-only keyless stamp. It uses the stored step
hash and stored request, not a hash or model binding recomputed from the
current configuration. A different request is not a saved-response hit.

The response is captured in the same write transaction that checks the saved
submission, before the existing attempt is claimed. A miss changes no attempt
or lease. A hit resumes that same attempt through the shared terminal writer
and submission finalizer. The response's original usage stays in its receipt;
recovery is memoized and creates no model backend, meter or budget admission.
Owner erasure still prevents a late terminal or submission from retaining the
response. No placeholder backend or zero-budget guard stands in for admission.

A new step, a Started-only checkpoint, an unavailable saved lookup or a
consumed budget trap with no saved response follows the existing inference
admission path. Exact-model selection, keyless/paid work attribution, the
physical run meter, logical allowance and retry policy are unchanged. No
current-format storage field, migration, default, cap or configuration is added.
