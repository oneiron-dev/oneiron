---
name: replay-observer
version: 1.0.0
verbs: ["claim.landed:local.hooks.trigger"]
actors: ["human"]
phase: fact
outcomes: ["nothing", "propose"]
---
Observe the original trigger and a stable scoped-read anchor, with pinned now.
