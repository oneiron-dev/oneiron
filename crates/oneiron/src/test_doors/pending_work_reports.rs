//! FIX 5558: doors for the pending-work-reports tests.
//!
//! A test records what one relay pass observed for a bundle publication,
//! as the relay itself keeps it: in memory on this handle, until the
//! handle closes. The executor's diagnostics then read it back.
//!
//! A test pages a re-assertion's keys by offset: the door appends extra
//! valid key records for the paging, and records the re-assertion's
//! request for a holder.

use std::collections::BTreeSet;

use oneiron_store::world_pad_codec::WorldKeyPad;

use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityOp, FIRST_GENERATION, MAX_PARENTS,
    OwnerWorkBody, PolicyRevision, WorldKeyMode, WorldKeyWrapsRecord, WrapRecipient,
    authority_entry_hash, invalid_authority, next_sequence, scope_head, sign_side_entry,
    standing_rows,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::world_keys::{
    OwnerWorkReceipt, PublishObserved, WorldKey, WorldKeyBinding, recipients, seal_world_key,
};
use crate::{EntityId, TimeRange, Vault};

/// Keeps `observed` as what a relay pass saw for the publication `request`,
/// by the home it reached. In memory only.
pub fn observe_bundle_publication(
    vault: &Vault,
    request: AuthorityEntryHash,
    observed: PublishObserved,
) {
    vault.observe_bundle_publication(request, observed);
}

/// Appends `count` valid key records of `world`, `machine`'s own wraps of
/// fresh mints at the generation past the first, each sealed to `machine`
/// with the doors' own seal under a pad that is never stored, naming the
/// evidence, chained and signed as the doors' own append does. Valid
/// no-ops: the fold keeps no key for them, but this install's own records
/// name every one, so a re-assertion's diagnostics page over them. The
/// caller names a world this install reads.
pub fn append_reassert_paging_keys(
    vault: &Vault,
    owner: EntityId,
    machine: EntityId,
    world: EntityId,
    count: usize,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let signing = vault.door_signing_key_in_txn(txn, machine)?;
        let signer = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        let to = WrapRecipient::Machine(machine);
        let public = recipients(&fold, world, None)
            .into_iter()
            .find_map(|(got, key)| (got == to).then_some(key))
            .ok_or_else(invalid_authority)?;
        let policy = PolicyRevision::of(
            fold.worlds
                .get(&world)
                .into_iter()
                .flat_map(|folded| folded.live.keys().copied()),
        );
        // The records' evidence, as the doors' own plan names it: the
        // world's live edits, this machine's standing, and the standing of
        // each live edit's author while few. No request, and no pinned
        // root here.
        let mut base: BTreeSet<AuthorityEntryHash> = fold
            .worlds
            .get(&world)
            .into_iter()
            .flat_map(|folded| folded.live.keys().copied())
            .collect();
        base.extend(standing_rows(&fold, machine));
        let authors: BTreeSet<AuthorityEntryHash> = fold
            .worlds
            .get(&world)
            .into_iter()
            .flat_map(|folded| folded.live.values())
            .flat_map(|author| standing_rows(&fold, *author))
            .collect();
        if base.union(&authors).count() <= MAX_PARENTS / 2 {
            base.extend(authors);
        }
        let mut chain = scope_head(&fold, &signer, world);
        let mut seq = next_sequence(&fold, &signer)?;
        let now = vault.instant_in_txn(txn)?.secs();
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            // A generation past the first: well-signed, so valid, but a
            // no-op the fold keeps no key for. The pad seals this record's
            // envelopes and is never stored, so the keys read as missing
            // their pads.
            let key = WorldKey::mint(world, FIRST_GENERATION + 1)?;
            let pad = WorldKeyPad::mint()?;
            let binding = WorldKeyBinding {
                vault_id,
                key: *key.id(),
                owner,
                policy,
                commitment: key.commitment(),
            };
            let envelope = seal_world_key(&binding, to, &public, &key, &pad)?;
            let record = WorldKeyWrapsRecord {
                key: *key.id(),
                commitment: key.commitment(),
                owner,
                policy,
                machine,
                wraps: vec![(to, envelope.to_bytes())],
                request: None,
                permitted: vec![to],
            };
            let mut parents = base.clone();
            parents.extend(chain);
            let entry = sign_side_entry(
                &fold,
                &signing,
                seq,
                parents,
                AuthorityOp::WorldKeyWraps(record),
                now,
            )?;
            seq = seq.checked_add(1).ok_or_else(invalid_authority)?;
            chain = Some(authority_entry_hash(&entry)?);
            rows.push((
                entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            ));
        }
        vault.put_authority_log_entries_in_txn(txn, &rows)?;
        Ok(())
    })
}

/// Records the owner's re-assertion of `world` for a holder, carried by
/// this install: a key-work request in Reassert mode for the world's
/// revision now, as the re-assertion's own door records it where this
/// install holds nothing. The fold names the executor; with none to name,
/// nothing is written and the receipt says why.
pub fn record_reassert_request(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    world: EntityId,
) -> Result<OwnerWorkReceipt> {
    vault.with_write_txn(|txn| {
        let seen = vault
            .authority_fold_readonly_in_txn(txn)?
            .world_policy_revision(world)
            .0;
        vault.record_owner_work_in_txn(
            txn,
            owner,
            ActSurface::HostedConsole,
            world,
            seen,
            OwnerWorkBody::WorldKey {
                mode: WorldKeyMode::Reassert,
            },
        )
    })
}
