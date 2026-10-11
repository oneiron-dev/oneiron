const message = JSON.parse("null");
await self.speak({text: message.text});
finish("sent");
