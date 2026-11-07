---
name: after-marker
version: 1.0.0
verbs: ["vault.claims.upsert"]
actors: ["human"]
phase: post
priority: 10
outcomes: ["continue", "propose"]
---
Only the independent pending predicate participates. Other owner calls continue.
