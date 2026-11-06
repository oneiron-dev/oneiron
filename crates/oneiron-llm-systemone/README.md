# System One seat wire contract

This crate implements `oneiron::llm::decision::DecisionSeat`, not `LlmBackend::generate`.
The caller must supply a `BudgetLease`, an access-scoped JSON **object** for `state`, a
versioned `DecisionQuestion` with its own instructions, and score-level labels for a
score question. Calls are allowed only at `PreQuery` or `Background` phases. The
`managed` posture or explicit remote opt-in is required; `relay` never calls remote.

Wire reference: [TypeSafe System One HTTP API](https://docs.typesafe.ai/api.md),
`POST /v1/systemone` (checked 2026-09-26). The single-question request uses `Authorization: Bearer`,
`model: "<model>-<pinned version>"`, `state: { ... }`, and one named question under
`questions.decision` with `type`, `instructions`, and where needed `criteria`:

- `noul`: criteria `{ "true": <what a yes means>, "false": <what a no means> }`, sent
  when the call's state carries a question's criteria triple (`yes_if_all`,
  `no_if_any`, `not_a_reason_to_say_no`; re-checked 2026-10-17); response
  `{ "type": "noul", "noul": <P(yes)> }`.
- `choice`: criteria maps each offered choice to `null`; response has `type`,
  `choice`, `probabilities` for each offered key, and `confidence`.
- `score`: criteria is an ordered list of 2–10 caller-provided labels; response
  has `type`, `score` (0 to `levels-1`), `legend`, indexed `probabilities`, and
  `confidence`. The adapter maps the score linearly to the caller's `[min,max]`.

A single-question response must contain `model: "<model>-<pinned version>"` and exactly one entry in
`answers.decision`. Missing, malformed, out-of-range, unoffered, or wrong-version
answers fail closed. `usage` reports per-measurement input and output tokens. The typed-decision
orchestrator admits a fresh `BudgetGuard` lease per measurement and settles each
one from these counts; failed calls settle their reserved charge. When budget
denies the optional recheck, the decision holds without another HTTP call.

The server's System One rung also observes an explicit retrieval cancellation while
waiting on a caller-run measurement. Cancellation stops that local wait; it does
not prove that the remote provider stopped work or waived its charge. The
already-dispatched measurement settles as failed and keeps its reserved charge.

The host owns its budget policy and retry policy. The decision receipt records the model
and exact version per measurement. A confident negative accept-type noul is
measured twice when separately admitted. A disagreement or a noul band hit
holds; choice and score hold below the band's upper confidence threshold.

## Packed reads

`SystemOneSeat::ask_pack` sends several typed questions over one caller-prepared
state and one shared set of image assets. The wire names are `q0`, `q1`, and so on,
in request order. Each question keeps its own instructions, answer contract and
score labels. The posture, opt-in, phase and media checks are the same as for a
single-question request. The server's System One rung uses this path for a
`DecisionPack`; unsupported score rows still abstain without a send.

One packed HTTP request has one admitted lease and one aggregate `usage` report.
The host settles that lease once. Individual predictions carry no token usage or
invented share of the pack's cost. The model and response envelope must be valid;
a missing or malformed answer for one wire name abstains only that question,
without discarding the other valid answers. Transport or whole-envelope failures
retain the existing failed-call settlement and ladder error handling. Existing
single-question reads and their separately admitted rechecks are unchanged.
