---
name: hooksandbox.probe
version: 1.0.0
description: Independent foreign hook sandbox and author-scope fixture
kind: capability
license: Apache-2.0
predicates: ["hooksandbox.probe.file", "hooksandbox.probe.network", "hooksandbox.probe.secret", "hooksandbox.probe.kind", "hooksandbox.probe.offer", "hooksandbox.probe.pending", "hooksandbox.probe.effect"]
grants: []
hooks: ["file-attempt", "network-attempt", "secret-attempt", "kind-escape", "offer-marker", "saved-question", "after-marker"]
---
Foreign code with local synthetic targets. Permissions come from the real
owner's explicit grants, never from this declaration or the installing caller.
