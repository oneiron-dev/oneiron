const receipt = await self.speak({text: "Synthetic check complete."});
const visible = [receipt].find(item => item.isVisible);
if (visible !== undefined) {
  console.log(visible.order);
}
finish({delivered: receipt.isVisible});
