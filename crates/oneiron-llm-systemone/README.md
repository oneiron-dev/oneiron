# System One seat wire contract

This crate implements `oneiron::llm::decision::DecisionSeat`, not `LlmBackend::generate`.
The caller must supply a `BudgetLease`, an access-scoped JSON **object** for `state`, a
versioned `DecisionQuestion` with its own instructions, and score-level labels for a
score question. Calls are allowed only at `PreQuery` or `Background` phases. The
`managed` posture or explicit remote opt-in is required; `relay` never calls remote.

Wire reference: [TypeSafe System One HTTP API](https://docs.typesafe.ai/api.md),
`POST /v1/systemone` (checked 2026-09-26). The request uses `Authorization: Bearer`,
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

The response must contain `model: "<model>-<pinned version>"` and exactly one entry in
`answers.decision`. Missing, malformed, out-of-range, unoffered, or wrong-version
answers fail closed. `usage` reports per-measurement input and output tokens. The typed-decision
orchestrator admits a fresh `BudgetGuard` lease per measurement and settles each
one from these counts; failed calls settle their reserved charge. When budget
denies the optional recheck, the decision holds without another HTTP call.
The host owns its budget policy and retry policy. The decision receipt records the model
and exact version per measurement. A confident negative accept-type noul is
measured twice when separately admitted. A disagreement or a noul band hit
holds; choice and score hold below the band's upper confidence threshold.
