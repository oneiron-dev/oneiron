---
name: oneiron.line
description: LINE Official Account channel identity adapter
version: 0.1.0
kind: connector
adapter: built-in:line
grants: ["channel_identity.line.provision", "channel_identity.line.inbound"]
wakes: ["surface_event.dispatch.v1"]
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
