const receipt = self.speak({text: "Synthetic check complete."});
finish({delivered: receipt.isVisible});
