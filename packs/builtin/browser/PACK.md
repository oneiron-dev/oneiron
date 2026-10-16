---
name: oneiron.browser
description: Agent browser connector: drives an isolated browser guest through code mode, for services with no API
version: 0.1.0
kind: connector
adapter: built-in:browser
grants: ["browser.browse"]
effects: ["browser.send", "browser.pay", "browser.account", "browser.publish", "browser.destructive"]
wakes: []
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
The browser runs in an isolated guest bound to the vault, the actor and the run. Its
profile and site sign-in state stay inside that guest and never enter the runner.
Each send-class action crosses the vault's grant for its effect class: a press per
send, one press for a reviewed batch, or none. A payment keeps a person's press.
Every effect lands a receipt naming the page it acted on.
