# W7-C02 PackByteMap foundation

Owner explicitly requested the first lawful runtime-pack foundation. ARCH-0058 §6's older “reserved until first pack” state is a trigger to implement it now, not a reason to defer it.

The implementation keeps global names and exact source/schema identity in every instance. Local u8 handles are only interning values. A content-addressed ordinary ASSET snapshot is the entity/sync/export carrier; a local hash-only head pin authorizes the local projection. Imported carrier data does not activate code or install kinds. Existing NOTE is not a lawful carrier because it is closed to opinion/take plus actor attribution.

Atomic lowest-free allocation, name collision refusal, retained inactive slots, safe entity-table GC, persistent name tombstones and slot generations prevent existing rows from changing meaning. Raw/public and replicated batch doors require name-bearing instance bodies; replay remaps by name. No static pack-half byte and no u16 extension.

C12 owns all v3.1 family/rekey work. Its tree was read only. Merge the tiny Store validation changes against its registry rather than replacing its allocation/rekey implementation.

Canon amendments needed after integration: document the first-pack ASSET carrier and local data/authority split; replace “not built” only when the root source-catalog and serialization/sync composition pass. Overflow uses local byte247 as the shared carrier only after lowest-free allocation fills the120 slots. The globally named kind plus per-allocation generation discriminates subtypes; GC never reassigns a stale envelope to another kind. This is local allocation policy, not a static entity-type identity. Define authenticated own-device automatic configuration adoption separately from foreign data import. Exact same-name source upgrades currently refuse; use versioned names or design an explicit old-identity-preserving protocol.

Initial syntax/format check passed. Focused compile/runtime validation is in progress,
not yet accepted. Root integration preserves the independent source-asset immutability
check, adds typed credential-nulled pack archive payloads, canonical hex identities,
and name-based JSON restore against an already locally admitted package. A foreign
archive never installs kinds. The source ASSET/map carrier still round-trips as DATA.
Sync composition and the production owner-consent catalog caller remain in progress.
See `impl-notes/W7-C02.md` for final observed results; old draft proposals are not tests.
