---
name: try-restore
version: 1.0.0
verbs: ["vault.claims.list"]
actors: ["human"]
phase: post
priority: 10
outcomes: ["continue", "annotate"]
---
Try to restore the hidden property by mutating this hook's input copy.
