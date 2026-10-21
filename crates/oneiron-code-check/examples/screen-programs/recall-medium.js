// Source: crates/oneiron-server/src/api/tests/mcp_quickjs.rs:414-415
const pack = await self.memory.recall({
  query: "heron lantern", effort: "medium", scope: {}
});
finish(JSON.stringify(pack));
