# System One seat wire contract

This crate implements `oneiron::llm::decision::DecisionSeat`, not `LlmBackend::generate`.
The caller must supply a `BudgetLease`, an access-scoped JSON **object** for `state`, a
versioned `DecisionQuestion` with its own instructions, and score-level labels for a
score question. Calls are allowed only at `PreQuery` or `Background` phases. The
`managed` posture or explicit remote opt-in is required; `relay` never calls remote.

Wire reference: [TypeSafe System One HTTP API](https://docs.typesafe.ai/api.md),
`POST /v1/systemone` (checked 2026-09-26). The request uses `Authorization: Bearer`,
`model: "jev-<pinned version>"`, `state: { ... }`, and one named question under
`questions.decision` with `type`, `instructions`, and where needed `criteria`:

- `noul`: no criteria; response `{ "type": "noul", "noul": <P(yes)> }`.
- `choice`: criteria maps each offered choice to `null`; response has `type`,
  `choice`, `probabilities` for each offered key, and `confidence`.
- `score`: criteria is an ordered list of 2–10 caller-provided labels; response
  has `type`, `score` (0 to `levels-1`), `legend`, indexed `probabilities`, and
  `confidence`. The adapter maps the score linearly to the caller's `[min,max]`.

The response must contain `model: "jev-<pinned version>"` and exactly one entry in
`answers.decision`. Missing, malformed, out-of-range, unoffered, or wrong-version
answers fail closed. `usage` is vendor metadata, not a local budget settlement;
the host owns accounting and retry policy. The decision receipt records the model
and exact version per measurement. A confident negative accept-type noul is
measured twice; a disagreement or a band hit holds instead of accepting.
