// Source: crates/oneiron-server/src/api/tests/mcp_quickjs/run_rows.rs:9-20
const seen = [];
try {
  await self.memory.search({query: "heron lantern"});
  seen.push("searched");
} catch (error) {
  seen.push("search refused");
}
try {
  await self.memory.put_claim({
    id: "000000000000000000000000000000c1",
    predicate: "profile.favorite_drink",
    subject: "000000000000000000000000000000b1",
    value: "tea"
  });
  seen.push("claimed");
} catch (error) {
  seen.push("claim refused");
}
finish(seen.join(", "));
