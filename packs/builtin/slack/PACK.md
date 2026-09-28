---
name: oneiron.slack
description: Slack shared-presence channel identity adapter
version: 0.1.0
kind: connector
adapter: built-in:slack
grants: ["channel_identity.slack.provision", "channel_identity.slack.inbound", "outbound.slack.send"]
wakes: ["surface_event.dispatch.v1"]
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
