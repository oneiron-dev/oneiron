# Question-call budgets

`question_call_budget_ms` is the existing vault learning setting. The owner
sets a seed or pin with `vault.settings.learning.put` and withdraws it with
`vault.settings.learning.clear`. Its precedence stays pin, fitted value with
own runs, owner seed, then catalog seed.

The scheduled self-heal detector and served critic review also read this
setting. An owner or fitted override supplies their decision-call clock, rounded
to milliseconds within the setting's existing bounds. Without an override they
keep their shipped clocks: 20 seconds for a detector question and 30 seconds for
a critic lens. Clearing an owner row exposes any fitted value still standing;
only catalog fallback retains the host clock.

The shared reader `question_call_budget_with_fallback` returns an explicit
`Duration` unchanged and without a settings lookup. A settings storage error
propagates through the consumer's existing error path; it does not select a
fallback. No new key, stored format, numeric default, or admission rule is added.
Standing questions and graph asks keep their existing `question_call_budget`
reader, including its catalog seed and explicit millisecond choices.
