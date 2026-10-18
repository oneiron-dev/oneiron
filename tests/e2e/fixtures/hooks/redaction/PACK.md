---
name: local
description: Ordered caller-view redaction fixture
version: 1.0.0
license: Apache-2.0
kind: capability
predicates: ["local.hooks.profile"]
hooks: ["hide-private", "try-restore"]
---
Two post hooks on one typed public read. They do not write source objects.
