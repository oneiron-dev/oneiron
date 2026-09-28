---
name: fixture.echo
description: echo connector fixture
version: 1
kind: connector
adapter: script:scripts/adapter.js
grants: ["email"]
wakes: ["email.arrived"]
---
