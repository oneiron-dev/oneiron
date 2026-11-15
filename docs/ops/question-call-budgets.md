# Question-call budgets

`question.call_budget_ms` is the existing learned setting key. The owner
sets a value row (a seed, with its weight in runs) or a pin with
`vault.settings.set`, and clears a row with a set whose value is absent or
null. Its precedence stays pin, fitted value with own runs, owner value row,
then the default.

Set it over the facade or MCP (`POST /v1/core/facade/vault.settings.set`)
with the key, the scope, the value, and `pin` for a pin (`weight_runs` for
a value row, which a learned key requires):

```json
{"key": "question.call_budget_ms", "scope": {"kind": "vault"}, "pin": true, "value": 20000}
```

The scheduled self-heal detector and served critic review also read this
setting. An owner or fitted override supplies their decision-call clock, rounded
to milliseconds within the setting's existing bounds. Without an override they
keep their shipped clocks: 20 seconds for a detector question and 30 seconds for
a critic lens. Clearing an owner row exposes any fitted value still standing;
only the default retains the host clock.

The shared reader `question_call_budget_with_fallback` returns an explicit
`Duration` unchanged and without a settings lookup. A settings storage error
propagates through the consumer's existing error path; it does not select a
fallback. The key's dotted name aside, no stored format, numeric default, or
admission rule is added. Standing questions and graph asks keep their
existing `question_call_budget` reader, including its default and explicit
millisecond choices.
