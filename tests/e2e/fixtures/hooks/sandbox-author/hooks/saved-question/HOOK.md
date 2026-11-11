---
name: saved-question
version: 1.0.0
verbs: ["vault.claims.upsert"]
actors: ["human"]
phase: pre
priority: 10
outcomes: ["continue", "ask"]
---
Only the independent pending predicate participates. Other owner calls continue.
