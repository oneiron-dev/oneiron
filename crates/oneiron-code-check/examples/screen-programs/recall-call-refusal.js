// Source: crates/oneiron-server/src/api/tests/mcp_quickjs/call_mode.rs:10-13
const pack = await self.memory.recall({
  query: "heron lantern", effort: "call", deadline_ms: 30000, scope: {}
});
let refused = "reached";
try {
  await self.memory.recall({
    query: "heron lantern", effort: "call", deadline_ms: 0, scope: {}
  });
} catch (error) {
  refused = String(error);
}
finish(JSON.stringify({pack, refused}));
