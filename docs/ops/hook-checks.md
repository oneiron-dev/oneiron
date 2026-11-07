# Hook cycle and depth checks

The owner can read saved runtime-hook cycle and depth checks through either door:

- `GET /v1/owner/hooks/checks`
- `vault.hooks.checks` through the facade, MCP or generated SDK, with `{}` as input.

Both return a JSON array of `HookCheck` records. Each record contains `binding`,
`run_key`, `reason` (`cycle` or `depth`), `chain` and `raised_at`. Each lineage link
contains its binding, run key, entity reference and source position. No hook body,
arguments, result values or source content is included.

The list keeps the native `Vault::hook_checks` order (oldest key first) and its
existing limit of 1,000 records. Reading does not dismiss a check, alter its
lineage, change a binding or stop a run. A cycle or deep chain continues to raise
an owner check without blocking the run, as before. This surface adds no new
threshold, retention rule, acknowledgement or automatic response.

The HTTP owner door and host facade require the live authenticated owner. The
facade checks owner proof before verb hooks. The engine rechecks the same proof
in the read transaction that reads the checks. Native embedded calls use their
actual embedded owner proof; caller-supplied owner identifiers are not accepted.
The owner HTTP route runs the same logical verb's hooks once.

Deploy the engine/server and generated SDK clients together. No vault migration,
new side table or QuickJS artifact rebuild is needed.
