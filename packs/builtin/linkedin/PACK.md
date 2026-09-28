---
name: oneiron.linkedin
description: LinkedIn MCP connector and inbox adapter
version: 0.1.0
kind: connector
adapter: built-in:linkedin
grants: ["linkedin.inbox.read", "linkedin.send_dm", "linkedin.connect_request"]
wakes: ["linkedin_inbox_sync", "surface_event.dispatch.v1"]
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
