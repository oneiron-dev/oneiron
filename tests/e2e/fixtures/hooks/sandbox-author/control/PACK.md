---
name: local
version: 1.0.0
description: Independent owner control for foreign hook progress
kind: capability
license: Apache-2.0
predicates: ["local.hooks.sandboxcontrol", "local.hooks.sandboxcontrol.observed"]
hooks: ["progress-control"]
---
An explicitly owner-installed local control, never foreign publisher authority.
