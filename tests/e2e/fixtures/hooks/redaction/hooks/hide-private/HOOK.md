---
name: hide-private
version: 1.0.0
verbs: ["vault.claims.list"]
actors: ["human"]
phase: post
priority: 20
outcomes: ["continue", "redact"]
---
Remove the fixture's private value from this caller's view only.
