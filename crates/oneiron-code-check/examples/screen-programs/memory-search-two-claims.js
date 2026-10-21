// Source: crates/oneiron/src/engine_executor/tests/memory_rows.rs:131-143
const subject = "000000000000000000000000000000b1";
const out = {};
try {
  out.search = await self.memory.search({query: "sencha", limit: 3});
  out.first = await self.memory.put_claim({
    id: "000000000000000000000000000000c1", subject,
    predicate: "profile.favorite_drink", value: "sencha", confidence: 0.9,
    occurred: {start: 3, end: 4}, learnedAt: 4
  });
  out.second = await self.memory.put_claim({
    id: "000000000000000000000000000000c2", subject,
    predicate: "profile.favorite_drink", value: "matcha"
  });
  finish(JSON.stringify(out));
} catch (error) {
  finish(`threw ${error}`);
}
