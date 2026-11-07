# Runtime hook regeneration on engine upgrades

With the `code-sandbox-wasmtime` feature, plain and embedded serve can
prepare replacements for a vault's own hooks after the verb table or hook sandbox
contract changes. Existing hooks keep running their last good bodies. This does
not update hub packs.

## Configure generation

Set `skills.hook_regen_prompt` in the server configuration or owner settings file.
Plain serve can also read `ONEIRON_SKILLS_HOOK_REGEN_PROMPT`. The value is the complete system
instruction for writing a replacement hook JavaScript body. No instruction or
model is built into this mechanism. An unset prompt starts no pass and spends
nothing. A supplied prompt must not be blank.

The request uses the configured generative chat seat and its existing policy,
model routes, owner fallbacks, receipts and per-turn budget. Its purpose is
`hook_regen`. Each binding's real author supplies the budget attribution; it is
not an owner credential or an adoption stamp. Request input includes the binding,
pack, hook, selector, intent, last good body, target contract hashes, current
hook WIT. Hooks have no verb-call import; the unrelated full code-mode catalog
is not sent. The system instruction must ask for the raw
JavaScript body, not Markdown fences or a JSON wrapper.

## One pass, pending decisions only

On each start with hooks enabled, a tracked background pass snapshots
`Vault::hooks_due_for_regen`. It visits the due bindings sequentially under the
same vault's housekeeping admission and uses that vault's shared hook sandbox.
No recurring timer or automatic retry is added. `--no-hooks` also disables this
pass. Generation does not delay the ready signal.

The existing engine regeneration path replays its newest 256 saved runs under
both the old and candidate bodies. It records `AutoAdopt`, `NeedsHumanStamp` or
`RolledBack` on the existing regeneration record. **`AutoAdopt` here is a pending
decision, not an installed replacement.** No startup owner proof is fabricated.
Failures retain the last good body. A shutdown cancels an outstanding generation
wait and joins the current replay/record write before model shutdown.

Use the existing owner doors:

- `vault.hooks.regen.due` lists bindings needing regeneration.
- `vault.hooks.regen.get` reads a binding's record and candidate hash.
- `vault.hooks.regen.adopt` adopts that exact candidate through the ordinary pack
  put path. A changed fingerprint needs the owner's own stamp. Generated-origin
  calls cannot supply it. A Candidate or Blocked install does not advance the
  last good body or contract stamp.

An unavailable model or a failed generation does not stop the server or install
an empty hook. The owner can inspect the pending failure and restart a configured
host to try again. Managed-serve startup wiring awaits its retained-handle teardown integration.
Lens regeneration and automatic enactment are separate work; this pass implements
neither.
