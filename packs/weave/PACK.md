---
name: oneiron.weave
description: The weave report lens: what changed for each reader, worded by the weave-report skill
version: 0.1.0
license: Apache-2.0
kind: capability
lenses: ["weave-report"]
---

The weave report is a lens over the vault. Its render is a generate step: the
engine reads a reader's report under that reader's own read, the
`weave-report` skill words and groups its items, and the engine composes the
card from them. The engine renders this lens in code, so its folder carries no
compiled tree and no component. The pack requests no grants and binds no wake.
