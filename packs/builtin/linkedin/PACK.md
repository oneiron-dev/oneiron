---
name: oneiron.linkedin
description: LinkedIn MCP connector and inbox adapter
version: 0.1.0
kind: connector
adapter: built-in:linkedin
grants: ["linkedin.inbox.read", "linkedin.send_dm", "linkedin.connect_request"]
wakes: ["linkedin_inbox_sync", "surface_event.dispatch.v1"]
setup: {"skill":"setup","accounts":[{"id":"linkedin","label":"Your LinkedIn account","sign_up":"https://www.linkedin.com/signup","note":"The connector acts as you, and LinkedIn may limit an account it judges automated."}],"connections":[{"id":"linkedin-session","label":"LinkedIn session","account":"linkedin","auth":"session","connector":"linkedin","secrets":[{"name":"linkedin.session_cookie","label":"LinkedIn session cookie","effector":"connector:linkedin","hint":"Taken from a browser where you are signed in to LinkedIn. You sign in yourself, and your password never reaches the vault."}],"permissions":[{"id":"inbox","grant":"linkedin.inbox.read","what":"Read your LinkedIn messages","risk":"Your private LinkedIn conversations are copied into your vault.","level":"high"},{"id":"message","grant":"linkedin.send_dm","what":"Send LinkedIn messages as you","risk":"Messages go out under your name, and LinkedIn may restrict an account that sends many.","level":"high"},{"id":"connect","grant":"linkedin.connect_request","what":"Send connection requests as you","risk":"Requests go out under your name, and LinkedIn limits how many one account may send.","level":"high","optional":true}],"verify":"linkedin.session"}]}
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
