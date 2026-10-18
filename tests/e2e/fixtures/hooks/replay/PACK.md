---
name: local
description: Deterministic replay observation fixture
version: 1.0.0
license: Apache-2.0
kind: capability
predicates: ["local.hooks.trigger", "local.hooks.anchor", "local.hooks.observation"]
hooks: ["replay-observer"]
---
A local fact hook used only by HOOKS-02. No inference or outbound effects.
