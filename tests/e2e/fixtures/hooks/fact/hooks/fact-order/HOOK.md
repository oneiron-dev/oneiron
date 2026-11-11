---
name: fact-order
version: 1.0.0
verbs: ["claim.landed:fact.hooks.input"]
actors: ["human"]
scope: "world:a1010000000000000000000000000010"
phase: fact
outcomes: ["propose"]
---
Propose one observation per matching landed claim, in its source commit order.
