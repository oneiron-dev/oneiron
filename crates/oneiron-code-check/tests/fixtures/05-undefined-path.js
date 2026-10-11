const receipt = await self.speak({text: "Synthetic check complete."});
const visible = [receipt].find(item => item.order === 1);
console.log(visible.order);
finish({delivered: receipt.isVisible});
