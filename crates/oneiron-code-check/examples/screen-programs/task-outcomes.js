// Source: crates/oneiron-server/src/api/tests/mcp_quickjs/device_local.rs:356-360
const pairs = await self.memory.tasks.outcomes({
  group_ref: "000000000000000000000000000000d1"
});
finish(String(pairs.length));
