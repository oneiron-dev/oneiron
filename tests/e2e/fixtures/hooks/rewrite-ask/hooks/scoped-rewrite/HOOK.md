---
name: scoped-rewrite
version: 1.0.0
verbs: ["vault.claims.upsert"]
actors: ["agent"]
phase: pre
priority: 20
outcomes: ["rewrite"]
---
Rewrite one scoped write without acquiring any caller authority.
