# Retrieval producer attribution

A canonical executor `self.memory.search` records its dispatching attempt in
`RetrievalRunRecord.dispatch_attempt` when its host dispatcher holds the native
leased-agent binding. The value comes from that binding, not a guest argument,
a run id, a parent label, or the current actor. It is diagnostic data, not read
authority. Search results, scoped filtering, and served-world accounting are unchanged.

The self-heal finding and clean-window consumers use this link only when every
run in a nonempty window names the same attempt. An unknown or different attempt
leaves the window on its existing Config/Unknown producer path. The existing
producer binder still requires that attempt to resolve to one active skill;
this change does not infer which skill caused a result.

Other retrieval entry points keep an unknown attempt unless their own native
caller captures one. No default or current policy manifest is stamped. Policy
manifest attribution and execution-bound pipeline attribution remain separate
work. No new hold, refusal, retry, or read permission is introduced.
