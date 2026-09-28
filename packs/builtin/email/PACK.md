---
name: oneiron.email
description: Email channel identity and delegated Gmail read adapter
version: 0.1.0
kind: connector
adapter: built-in:email
grants: ["channel_identity.email.provision", "channel_identity.email.inbound", "mail.read"]
wakes: ["surface_event.dispatch.v1"]
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
