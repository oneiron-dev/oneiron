const id = "01010101010101010101010101010101e1";
const subject = "01010101010101010101010101010101e2";
const receipt = await self.memory.put_claim({id, predicate:"test.quickjs", subject, value:{answer:42}});
const edge = await self.memory.put_edge({src:id, kind:"about", tgt:subject, weight:0.5});
finish({id: receipt.id, target: edge.tgt});
