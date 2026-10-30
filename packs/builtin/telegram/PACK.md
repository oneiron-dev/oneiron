---
name: oneiron.telegram
description: Telegram bot outbound adapter, with reply-as-you through Telegram Business
version: 0.1.0
kind: connector
adapter: built-in:telegram
grants: ["outbound.telegram.send"]
wakes: []
setup: {"skill":"setup","accounts":[{"id":"telegram-bot","label":"A Telegram bot made with @BotFather","sign_up":"https://t.me/BotFather","note":"BotFather makes the bot and gives its token. Reply-as-you needs Telegram Premium and the bot connected under Settings, Telegram Business, Chatbots."}],"connections":[{"id":"telegram-bot","label":"Telegram bot","account":"telegram-bot","auth":"bot_token","connector":"telegram","secrets":[{"name":"telegram.bot_token","label":"Bot token","effector":"connector:telegram","hint":"Given by @BotFather when you make the bot, and again by its /token command."}],"permissions":[{"id":"send","grant":"outbound.telegram.send","what":"Send messages as the bot to the people and chats that let it message them","risk":"A wrong or hasty message reaches the person at once, and people may read it before it is deleted.","level":"high"},{"id":"reply-as-you","grant":"outbound.telegram.send","what":"Answer the business chats you connected the bot to as you, under your own name","risk":"People read these answers as yours and cannot tell the agent wrote them.","level":"high","optional":true}],"verify":"telegram.get_me"}]}
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
