---
name: oneiron.native_mail
description: Native mail provisioning, JMAP inbox intake and reputation on a per-owner Stalwart instance
version: 0.1.0
kind: connector
adapter: built-in:native_mail
grants: ["channel_identity.email.provision", "channel_identity.email.inbound", "mail.read", "mail.send"]
wakes: ["surface_event.dispatch.v1"]
---
