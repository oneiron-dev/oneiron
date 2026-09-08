//! Vault persistence and amendment for the channel-identity selection rule set.

use heed::RoTxn;

use crate::Vault;
use crate::overlay_db::OverlayDb;

use super::selection_codec::{decode_rule_set, encode_rule_set};
use super::selection_resolution::{
    ChannelIdentitySelectionError, ChannelIdentitySelectionPatch, ChannelIdentitySelectionResult,
    builtin_channel_identity_selection_rules, compile_channel_identity_selection,
};
use super::selection_rules::{
    ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet, ChannelIdentitySelectionWriter,
};
use super::selection_vocabulary::{
    CHANNEL_IDENTITY_SELECTION_KEY, CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
    SelectionRuleWriterKind,
};

// ---------------------------------------------------------------------------
// Storage + amendment
// ---------------------------------------------------------------------------

fn stored_rule_set(
    vault_meta: &OverlayDb,
    txn: &RoTxn<'_>,
) -> ChannelIdentitySelectionResult<Option<ChannelIdentitySelectionRuleSet>> {
    match vault_meta.get(txn, CHANNEL_IDENTITY_SELECTION_KEY)? {
        Some(raw) => decode_rule_set(&raw).map(Some),
        None => Ok(None),
    }
}

/// Applies one patch to the stored overlay rows under writer authority.
fn apply_patch(
    rows: &mut Vec<ChannelIdentitySelectionRule>,
    builtins: &[ChannelIdentitySelectionRule],
    writer: &ChannelIdentitySelectionWriter,
    patch: ChannelIdentitySelectionPatch,
) -> ChannelIdentitySelectionResult<()> {
    match patch {
        ChannelIdentitySelectionPatch::Upsert(mut rule) => {
            // Provenance is DERIVED here, so whatever the caller put in these
            // two fields is overwritten rather than trusted.
            rule.writer_kind = writer.kind();
            rule.updated_by = Some(writer.actor_ref());
            rule.validate()?;
            let existing = rows
                .iter()
                .find(|row| row.rule_id == rule.rule_id)
                .or_else(|| builtins.iter().find(|row| row.rule_id == rule.rule_id));
            authorize_upsert(writer, existing, &rule)?;
            match rows.iter().position(|row| row.rule_id == rule.rule_id) {
                Some(index) => rows[index] = rule,
                None => rows.push(rule),
            }
            Ok(())
        }
        ChannelIdentitySelectionPatch::Remove { rule_id } => {
            let Some(index) = rows.iter().position(|row| row.rule_id == rule_id) else {
                // A builtin is compiled law: it is disabled by upserting a
                // shadow with `enabled = false`, never deleted.
                return Err(if builtins.iter().any(|row| row.rule_id == rule_id) {
                    ChannelIdentitySelectionError::BuiltinRuleNotRemovable
                } else {
                    ChannelIdentitySelectionError::RuleNotFound
                });
            };
            authorize_write(writer, &rows[index])?;
            rows.remove(index);
            Ok(())
        }
    }
}

/// An agent may only touch rows that are currently agent-amendable, and may
/// never leave one locked behind it.
fn authorize_upsert(
    writer: &ChannelIdentitySelectionWriter,
    existing: Option<&ChannelIdentitySelectionRule>,
    next: &ChannelIdentitySelectionRule,
) -> ChannelIdentitySelectionResult<()> {
    if writer.kind() != SelectionRuleWriterKind::Agent {
        return Ok(());
    }
    if let Some(existing) = existing {
        authorize_write(writer, existing)?;
    }
    if next.agent_amendable {
        Ok(())
    } else {
        Err(ChannelIdentitySelectionError::AgentCannotLockRule)
    }
}

fn authorize_write(
    writer: &ChannelIdentitySelectionWriter,
    existing: &ChannelIdentitySelectionRule,
) -> ChannelIdentitySelectionResult<()> {
    if writer.kind() != SelectionRuleWriterKind::Agent || existing.agent_amendable {
        Ok(())
    } else {
        Err(ChannelIdentitySelectionError::RuleNotAgentAmendable)
    }
}

impl Vault {
    /// Reads the compiled selection law: stored overlay over the builtins.
    ///
    /// A fresh vault returns the six builtins at revision `0`. Corrupt storage
    /// fails typed rather than resolving against a guess.
    pub fn channel_identity_selection_rules(
        &self,
    ) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
        let rtxn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let stored = stored_rule_set(&self.store.vault_meta, &rtxn)?;
        compile_channel_identity_selection(stored.as_ref())
    }

    /// Amends the selection law under compare-and-swap on `expected_revision`.
    ///
    /// An accepted change stamps the derived writer kind and `updated_by` onto
    /// the row and advances the revision by exactly one. The whole read,
    /// authorization, compile, and write happen in one transaction, so two
    /// racing writers cannot both land against the same revision.
    pub fn update_channel_identity_selection_rules(
        &self,
        expected_revision: u64,
        writer: &ChannelIdentitySelectionWriter,
        patch: ChannelIdentitySelectionPatch,
    ) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
        let builtins = builtin_channel_identity_selection_rules();
        self.try_with_write_txn(|wtxn| {
            let stored = stored_rule_set(&self.store.vault_meta, &*wtxn)?;
            let current = stored.as_ref().map_or(0, |set| set.revision);
            if current != expected_revision {
                return Err(ChannelIdentitySelectionError::RevisionConflict {
                    expected: expected_revision,
                    stored: current,
                });
            }
            let mut rows = stored.map(|set| set.rows).unwrap_or_default();
            apply_patch(&mut rows, &builtins, writer, patch)?;
            rows.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
            let record = ChannelIdentitySelectionRuleSet {
                schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
                revision: current
                    .checked_add(1)
                    .ok_or(ChannelIdentitySelectionError::RevisionOverflow)?,
                rows,
            };
            // Compile BEFORE writing: an amendment that would make the
            // compiled law ambiguous is refused, not persisted and discovered
            // on the next read.
            let compiled = compile_channel_identity_selection(Some(&record))?;
            let bytes = encode_rule_set(&record)?;
            self.store
                .vault_meta
                .put(wtxn, CHANNEL_IDENTITY_SELECTION_KEY, &bytes)?;
            Ok(compiled)
        })
    }

    /// Reads the stored overlay exactly as persisted, without the builtins.
    ///
    /// Callers that need the law want [`Self::channel_identity_selection_rules`];
    /// this door exists for provenance inspection of what was actually written.
    pub fn stored_channel_identity_selection_rules(
        &self,
    ) -> ChannelIdentitySelectionResult<Option<ChannelIdentitySelectionRuleSet>> {
        let rtxn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        stored_rule_set(&self.store.vault_meta, &rtxn)
    }
}
