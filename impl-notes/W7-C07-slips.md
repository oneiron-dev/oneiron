# W7-C07 slips / pairing implementation handoff

Historical implementation handoff. Final acceptance and remaining-work status are recorded in [W7-C07.md](W7-C07.md) and supersede pending statements below.

Status: implementation handoff retained for design detail. The current integration state and test evidence are in [W7-C07.md](W7-C07.md); historical tasks below have been reconciled with the integrated source.

## Built

- `authority/slip.rs`: one serde CapabilitySlip, strict canonical `v2.slip.<lowerhex-json>` framing, pinned version 2, keyed-BLAKE3 initial MAC and MAC-as-key caveat chain. Only final MAC travels. MAC, committed base claims, current vault/fold/host liveness, lifetime and Ed25519 holder binding must all verify. Offline scope/expiry/TTL/records/channels meets never widen. A verifier-produced private-field VerifiedSlip derives DoorCredential. Manual `DoorCredential::verified` is test-only.
- `slip_state.rs`: mint table, parent narrowing validation, monotone revocation/consumption and deterministic conflict join. Parent kill denies descendants. One-shot child consumption also spends single-use ancestors and siblings. No caller may mint by writing device key residue.
- `slip_vault.rs`: HostSlipIssuer derives a separate signing key from retained auth_secret. Empty means truly zero authority records, not missing/conflicted fold root. Genesis recovery acknowledgement + root SlipMint + host-specific cache commit atomically. Existing root must match live issuer. New ReRoot host gets a new host-key-specific cache. Cached revoked root never remints. Public mint/revoke/atomic auth-consume methods all append signed log operations under the check transaction.
- `slip_pairing.rs`: 5-minute hash-at-rest one-use ticket, atomic mint+ticket delete, throwaway binding-key proof; public descriptor. Pairing issue gives one root slip (no device authority roster enrollment).
- Server boot obtains root slip before read gates. Production accepts actual capability slip + `x-oneiron-binding` JSON proof, or configured root secret proved through its logged root. String-claim v2 tokens are no longer production credentials. CLI token mint fails with the pairing route instructions; revoke accepts 64-hex log slip ids. Dev creates no root. App-tier auth.bind requires sibling `binding` proof. Sessions refold liveness.
- HTTP routes: `/.well-known/oneiron`, `/v1/core/pairing/links` (owner), `/v1/core/pairing/redeem` (ticket+key proof), `/v1/core/slips/revoke` (owner).
- Device lease registration now always refuses, even a valid old-device POP. SyncClient loads only client id and no longer emits a lease-request. Historical audit lease rows can still expire/be revoked; receipt origin-attestation compatibility remains separate and does not authorize a slip.
- CredentialDoorService with_host_issuer makes mint_one_shot real. Consuming log entry commits before secret materialization. Failed materialization can spend a one-shot; duplicate use cannot obtain a second value. This is failclosed at-most-once, not transactional rollback of a failed effect.

## Integration state

- `ScopedReadActorKey::from_verified_slip` exists. Scoped reads carry proof expiry and live authority; plain no-grant readers and named-world/base mismatches deny.
- SlipRevoke and SlipConsume bypass unrelated pending widens as withdrawals. The authority run passed their regressions.
- Production HTTP/app-tier fixtures now use actual logged slips and holder proofs. Device lease enrollment fixtures expect refusal; historical withdrawal and expiry remain covered.
- Adapters without record-Scope forwarding reject narrowed credentials rather than dropping their limits. MCP connector-registry authentication remains its separate pre-existing lane.
- HTTP admission and app-tier binding now atomically consume the holder nonce once. Downstream checks inside one admitted HTTP request remain read-only. HTTP single-use instruments remain refused; the explicit atomic credential door owns one-shot use. Replay regressions await runtime validation.
- Historical receipt-origin device keys remain forensic signature material, never enrollment authority. No slip mint/auth reads the device-lease residue.
- Public names remain under `oneiron::authority`. Current formatting/maps and complete native validation are tracked in the main note.

## Tests added / migrated (not run)

`authority::slip::tests::`:
- bootstrap_commits_genesis_and_slip_mint_and_reuses_one_root
- v2_roundtrip_tamper_and_missing_binding_deny
- offline_meet_order_and_ttl_expiry_never_widen
- log_mint_requires_parent_narrowing_and_revoke_kills_subtree
- log_single_use_burn_is_atomic_and_survives_fresh_decode
- pairing_link_mints_once_and_requires_connection_private_key
- one_1191_root_rotation_residue_cannot_mint_or_authorize
- consuming_child_spends_single_use_ancestor_and_siblings

`api::tests::slips::`:
- descriptor_is_unauthenticated_and_pairing_link_is_one_use
- v2_http_tamper_and_token_without_private_binding_refuse_401
- unlogged_mac_tokens_and_dev_tokens_never_become_production_slips

`credential_door::tests` fixtures now create real logged one-shots. Added signing_host_mints_and_redeems_one_shot_via_authority_log; replaced obsolete no-ledger-by-move assertion with a second-use refusal. Existing lifetime/floor/clock tests retained. Read-only door still tests MintUnavailable without issuer.

Suggested first native lanes once the missing actor constructor lands:
`cargo nextest run -p oneiron --all-features -E 'test(authority::slip::tests::) | test(credential_door::tests::)'`
`cargo nextest run -p oneiron-server -E 'test(api::tests::slips::)'`
Parent owns compile/fmt/full gate. All-features + featureless + server sync selections matter.

## Canon conflicts / decisions

The credential-door comment forbidding slip authority ops was obsolete for OF-452 D3 and is removed. Device POP was receipt provenance, not root authority; residue must never mint a capability. Retained auth_secret is explicitly the bootstrap recovery secret (a separate domain-derived commitment goes into Genesis), not a hidden second recovery hierarchy. ReRoot changes host signing authority, not vault identity. MAC caveat chains store only final MAC to prevent removing the last caveat. A root slip is held before no-grant read flips. Pre-GA means no fallback acceptance of old unlogged MAC tokens.

## Changed files
- `crates/oneiron/src/authority/slip.rs`
- `crates/oneiron/src/authority/slip_state.rs`
- `crates/oneiron/src/authority/slip_vault.rs`
- `crates/oneiron/src/authority/slip_pairing.rs`
- `crates/oneiron/src/authority/slip_tests.rs`
- `crates/oneiron/src/credential_door/door_credential.rs`
- `crates/oneiron/src/credential_door/door_service.rs`
- `crates/oneiron/src/credential_door/mod.rs`
- `crates/oneiron/src/credential_door/tests.rs`
- `crates/oneiron/src/sync/client/base.rs`
- `crates/oneiron/src/sync/client/sync_frames.rs`
- `crates/oneiron-server/src/auth.rs`
- `crates/oneiron-server/src/auth/slips.rs`
- `crates/oneiron-server/src/commands.rs`
- `crates/oneiron-server/src/server/core.rs`
- `crates/oneiron-server/src/server/leases.rs`
- `crates/oneiron-server/src/api/pairing.rs`
- `crates/oneiron-server/src/api/mod.rs`
- `crates/oneiron-server/src/api/scoped_auth.rs`
- `crates/oneiron-server/src/api/search.rs`
- `crates/oneiron-server/src/api/entity.rs`
- `crates/oneiron-server/src/api/facade.rs`
- `crates/oneiron-server/src/api/surface_events.rs`
- `crates/oneiron-server/src/api/conversations.rs`
- `crates/oneiron-server/src/api/run_tree.rs`
- `crates/oneiron-server/src/api/git_lfs/gate.rs`
- `crates/oneiron-server/src/api/git_http/gate.rs`
- `crates/oneiron-server/src/api/vad.rs`
- `crates/oneiron-server/src/api/context_board/mod.rs`
- `crates/oneiron-server/src/api/core/query.rs`
- `crates/oneiron-server/src/api/tests/slips.rs`
- `crates/oneiron-server/src/api/tests/mod.rs`
- `crates/oneiron-server/src/api/tests/memory_reason_repairs.rs`
- `crates/oneiron-server/src/api/tests/depth_quality.rs`
- `crates/oneiron-server/src/livequery.rs`
- `crates/oneiron-server/src/livequery/source.rs`
- `crates/oneiron-server/src/livequery/connection.rs`
- `crates/oneiron-server/src/handler/app_tier.rs`
