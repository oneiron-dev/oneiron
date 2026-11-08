---
name: saved-question
version: 1.0.0
verbs: ["vault.claims.upsert"]
actors: ["agent"]
phase: pre
priority: 10
outcomes: ["ask"]
---
Ask after the first hook's rewritten arguments have passed boundary validation.
