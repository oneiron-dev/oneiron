---
name: oneiron.email
description: Email channel identity and delegated Gmail read adapter
version: 0.1.0
kind: connector
adapter: built-in:email
grants: ["channel_identity.email.provision", "channel_identity.email.inbound", "mail.read"]
wakes: ["surface_event.dispatch.v1"]
setup: {"skill":"setup","accounts":[{"id":"google","label":"A Google account or Google Workspace mailbox","sign_up":"https://accounts.google.com/signup","note":"A Workspace admin may need to allow third-party apps to read Gmail."}],"connections":[{"id":"gmail","label":"Gmail mailbox","account":"google","auth":"oauth","connector":"gmail","secrets":[{"name":"gmail.oauth","label":"Gmail read grant","effector":"connector:gmail","hint":"Made when you sign in with Google and allow read access. Store what the sign-in returns, never your Google password."}],"permissions":[{"id":"read","scope":"https://www.googleapis.com/auth/gmail.readonly","grant":"mail.read","what":"Read the email in the mailbox","risk":"Every message in the mailbox, private ones included, becomes readable by your agent and is copied into your vault.","level":"high"},{"id":"identity","grant":"channel_identity.email.provision","what":"Use the mailbox address as your agent's email identity","risk":"People who write to the address reach your agent.","level":"medium"},{"id":"inbound","grant":"channel_identity.email.inbound","what":"Treat new mail as messages to your agent","risk":"Mail from strangers, phishing included, reaches your agent as a message.","level":"medium"}],"verify":"gmail.profile"}]}
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
