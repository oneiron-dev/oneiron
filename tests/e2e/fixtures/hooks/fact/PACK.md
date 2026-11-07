---
name: fact
description: Ordered fact commits across a real server restart
version: 1.0.0
license: Apache-2.0
kind: capability
predicates: ["fact.hooks.input", "fact.hooks.other", "fact.hooks.observation"]
hooks: ["fact-order"]
---
An independent HOOKS-01 corpus. No model, network or external effects.
