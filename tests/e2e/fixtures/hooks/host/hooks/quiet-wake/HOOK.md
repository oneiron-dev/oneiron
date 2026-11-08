---
name: quiet-wake
version: 1.0.0
verbs: ["host.wake"]
actors: ["human", "system"]
phase: pre
priority: 20
outcomes: ["skip"]
---
Keep the authored quiet-hours reason on the skipped wake's real receipt.
