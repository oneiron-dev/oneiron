---
name: oneiron.browser
description: Agent browser connector: drives an isolated browser guest through code mode, for services with no API
version: 0.1.0
kind: connector
adapter: built-in:browser
grants: ["browser.browse"]
effects: ["browser.send", "browser.pay", "browser.account", "browser.publish", "browser.destructive"]
wakes: []
setup: {"skill":"setup","connections":[{"id":"browser-guest","label":"The browser guest on this host","auth":"local","permissions":[{"id":"browse","grant":"browser.browse","what":"Open and read web pages in an isolated browser guest, and act on them under the press each kind of effect needs","risk":"Sites see this host's network address, and a site you sign in to inside the guest treats the agent's visits as yours.","level":"medium"}],"verify":"browser.session"}]}
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
The browser runs in an isolated guest bound to the vault, the actor and the run. Its
profile and site sign-in state stay inside that guest and never enter the runner.
Each send-class action crosses the vault's grant for its effect class: a press per
send, one press for a reviewed batch, or none. A payment keeps a person's press.
Every effect lands a receipt naming the page it acted on.
