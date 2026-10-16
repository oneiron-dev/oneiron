---
name: oneiron.line
description: LINE Official Account channel identity adapter
version: 0.1.0
kind: connector
adapter: built-in:line
grants: ["channel_identity.line.provision", "channel_identity.line.inbound"]
wakes: ["surface_event.dispatch.v1"]
setup: {"skill":"setup","accounts":[{"id":"line-oa","label":"A LINE Official Account with the Messaging API turned on","sign_up":"https://entry.line.biz/start/","note":"Turning on the Messaging API in LINE Official Account Manager makes the account's channel in the LINE Developers Console."}],"connections":[{"id":"line-channel","label":"LINE Messaging API channel","account":"line-oa","auth":"bot_token","connector":"line","secrets":[{"name":"line.channel_access_token","label":"Channel access token (long-lived)","effector":"connector:line","hint":"Issued on the channel's Messaging API tab in the LINE Developers Console."},{"name":"line.channel_secret","label":"Channel secret","effector":"connector:line","hint":"Shown on the channel's Basic settings tab in the LINE Developers Console."}],"permissions":[{"id":"identity","grant":"channel_identity.line.provision","what":"Use the Official Account as your agent's identity on LINE","risk":"Replies from the account speak for your agent, and its followers will treat them as yours.","level":"medium"},{"id":"receive","grant":"channel_identity.line.inbound","what":"Receive the messages people send the Official Account","risk":"Every message sent to the account, with the sender's LINE display name, is copied into your vault.","level":"medium"}],"verify":"line.bot_info"}]}
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
