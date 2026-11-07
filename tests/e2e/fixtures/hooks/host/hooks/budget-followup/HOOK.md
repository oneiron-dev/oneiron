---
name: budget-followup
version: 1.0.0
verbs: ["host.budget.hit"]
actors: ["human", "system"]
phase: post
priority: 20
outcomes: ["enqueue"]
---
Enqueue a follow-up that carries the original seat and accounting unchanged.
