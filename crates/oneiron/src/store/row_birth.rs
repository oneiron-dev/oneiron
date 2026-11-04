//! Row birth derivation envelopes and copy-scoped withheld identities.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use heed::RwTxn;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Most hex characters a birth's input hash may carry.
const MAX_CONTENT_HASH_HEX: usize = 128;

/// Hex characters of a withheld ref's keyed hash in its handle, after `wh_`
/// (64 bits; an open call in engine-calls-review/CALLS.md, "OF-491 Q26
/// handles").
const WITHHELD_HANDLE_HEX: usize = 16;

/// The birth envelope of one row: Rule A's `made_by` plus the derivation
/// memo-key's input hash (ARCH-0035, `content_hash`: the hash of the exact
/// input records and claims read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RowBirth {
    pub made_by: MadeBy,
    /// Lowercase hex of the hash of the exact inputs as read; empty for a
    /// stated birth that read nothing.
    pub content_hash: String,
    /// Refs a copy of this birth withholds from its destination
    /// ([`RowBirth::masked`]); empty in the vault's own birth row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld: Vec<WithheldRef>,
    /// The evidence refs a room write's caller supplied, as supplied (FIX
    /// 4281): bookkeeping only a room's own stamper keeps
    /// ([`room::stamp_room_birth_in_txn`]), never authenticated evidence. A
    /// base stamp treats it as absent, and no copy carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_evidence: Option<RoomEvidence>,
}

/// The evidence refs a room write's caller named, each with what the room
/// read it as (FIX 4281, Engine 10-22). A ref the room did not read as a
/// TURN is kept as supplied: the room accepts it, and it is no evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomEvidence {
    /// Every supplied ref, in the order given.
    pub refs: Vec<RoomEvidenceRef>,
}

/// One supplied evidence ref of a room write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomEvidenceRef {
    /// The ref as the caller spelled it.
    pub supplied: String,
    /// The 32 hex digits of the TURN the caller read it as in the room, one
    /// of the birth's inputs; `None` for a ref the room read as no TURN.
    pub turn: Option<String>,
}

/// A ref a birth names that its copy's destination may not see (Q26 = B): a
/// handle in its place, never the ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WithheldRef {
    /// `wh_` and 16 hex of the ref keyed by the copy's [`WithheldKey`]: one
    /// ref reads as one handle within a copy, and the handle never reverses.
    pub handle: String,
    pub role: WithheldRole,
}

/// What a withheld ref was in the birth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WithheldRole {
    Input,
    Prompt,
    Trigger,
}

/// One copy's masking key. An export takes a fresh one, so its handles link
/// to no other copy; a replicated birth, which its destination keeps
/// immutable, takes its destination's stable key, so a resync writes the same
/// handles.
pub struct WithheldKey([u8; 32]);

impl WithheldKey {
    #[must_use]
    pub fn fresh() -> Self {
        let mut key = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
        Self(key)
    }

    /// The key one export masks its births under: fresh, so no two exports
    /// link their handles (the open call "OF-491 Q26 handles" in
    /// engine-calls-review/CALLS.md).
    #[must_use]
    pub fn for_export() -> Self {
        Self::fresh()
    }

    /// The stable key for every copy bound for `destination`: the vault's
    /// local withheld secret, made on first use and never shipped, keys a
    /// hash of the destination bytes. One destination reads one ref as one
    /// handle on every sync; two destinations cannot join their handles.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub fn for_destination(vault: &crate::Vault, destination: &[u8]) -> Result<Self> {
        // Only the first call writes: once the secret exists, a read serves.
        let secret = {
            let txn = vault.store.env.read_txn()?;
            WITHHELD_SECRET.get(&vault.store, &txn, &())?
        };
        if let Some(secret) = secret {
            return Ok(Self::keyed(&secret, destination));
        }
        vault.with_write_txn_grouped(|txn| {
            Self::for_destination_in_txn(&vault.store, txn, destination)
        })
    }

    /// [`WithheldKey::for_destination`] inside the caller's transaction.
    pub(crate) fn for_destination_in_txn(
        store: &impl ManifestDbs,
        txn: &mut RwTxn<'_>,
        destination: &[u8],
    ) -> Result<Self> {
        let secret = if let Some(secret) = WITHHELD_SECRET.get(store, txn, &())? {
            secret
        } else {
            let secret = Self::fresh().0;
            WITHHELD_SECRET.put(store, txn, &(), &secret)?;
            secret
        };
        Ok(Self::keyed(&secret, destination))
    }

    fn keyed(secret: &[u8; 32], destination: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(secret);
        hasher.update(b"oneiron.provenance.withheld.destination.v1\0");
        hasher.update(destination);
        Self(*hasher.finalize().as_bytes())
    }

    fn handle(&self, row: &EntityId) -> String {
        format!(
            "wh_{}",
            &blake3::keyed_hash(&self.0, row.as_bytes()).to_hex()[..WITHHELD_HANDLE_HEX]
        )
    }
}

impl RowBirth {
    /// A stated birth: a person or an import wrote the row from nothing the
    /// engine read, so there is no prompt, trigger or input hash.
    #[must_use]
    pub const fn stated(made_by: MadeBy) -> Self {
        Self {
            made_by,
            content_hash: String::new(),
            withheld: Vec::new(),
            room_evidence: None,
        }
    }

    /// This birth as a copy carries it to a destination that sees only the
    /// rows `ships` admits (Q26 = B). Each input, and the trigger, whose row
    /// it refuses moves to `withheld` as a handle. Who made the row, by which
    /// process and when, and the input hash ship whole. A room's evidence
    /// refs never ship: they are the room's bookkeeping, as supplied.
    #[must_use]
    pub fn masked(&self, ships: impl Fn(&EntityId) -> bool, key: &WithheldKey) -> Self {
        let mut birth = self.clone();
        birth.room_evidence = None;
        let mut withheld = std::mem::take(&mut birth.withheld);
        birth.made_by.inputs.retain(|input| {
            if ships(&input.row) {
                return true;
            }
            withheld.push(WithheldRef {
                handle: key.handle(&input.row),
                role: match input.role {
                    MadeByInputRole::Input => WithheldRole::Input,
                    MadeByInputRole::Prompt => WithheldRole::Prompt,
                },
            });
            false
        });
        if let Some(row) = birth.made_by.trigger.as_ref().map(MadeByTrigger::row)
            && !ships(&row)
        {
            withheld.push(WithheldRef {
                handle: key.handle(&row),
                role: WithheldRole::Trigger,
            });
            birth.made_by.trigger = None;
        }
        birth.withheld = withheld;
        birth
    }

    /// This birth with each input and prompt ref, and the ref its trigger
    /// names, renamed by `rename`: a copy that lands a ref's row under
    /// another id names it by that id (FIX 3890). The trigger keeps its kind.
    /// Who made the row, by which process and when, the input hash and the
    /// refs it already withholds stay as they are. A room's evidence refs,
    /// spelled as supplied, are not renamed: the copy drops them.
    #[must_use]
    pub fn renamed_refs(&self, rename: impl Fn(EntityId) -> EntityId) -> Self {
        let mut birth = self.clone();
        birth.room_evidence = None;
        for input in &mut birth.made_by.inputs {
            input.row = rename(input.row);
        }
        if let Some(
            MadeByTrigger::Task(row)
            | MadeByTrigger::Ask(row)
            | MadeByTrigger::Run(row)
            | MadeByTrigger::Skill(row),
        ) = birth.made_by.trigger.as_mut()
        {
            *row = rename(*row);
        }
        birth
    }

    /// The birth of a row `actor` wrote through `door` at `at`, made from
    /// `inputs`, whose bytes as the door read them are `read`. It names no
    /// prompt or trigger: a door that has them builds its own envelope.
    /// `None` for a concluded birth that names no input: a concluded birth
    /// names what it was made from, and the door has nothing to name.
    pub(crate) fn written(
        actor: WriteActor,
        class: MadeByClass,
        door: &str,
        inputs: &[EntityId],
        read: &[&[u8]],
        at: u64,
    ) -> Option<Self> {
        if class == MadeByClass::Concluded && inputs.is_empty() {
            return None;
        }
        let mut seen = std::collections::BTreeSet::new();
        let named: Vec<MadeByInput> = inputs
            .iter()
            .filter(|row| seen.insert(**row))
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect();
        Some(Self {
            made_by: MadeBy {
                inputs: named,
                process: MadeByProcess {
                    actor: actor.entity_ref(),
                    class,
                    identity: door.to_owned(),
                    version: "1".into(),
                    // A write door takes no render parameters.
                    params_hash: format!("{:x}", Sha256::digest([])),
                },
                at,
                trigger: None,
            },
            content_hash: if read.is_empty() {
                String::new()
            } else {
                Self::content_hash_of(read)
            },
            withheld: Vec::new(),
            room_evidence: None,
        })
    }

    /// Whether this is a document birth: the stand-in a document's first
    /// commit stamps when no door stamped the row (`entity_doc`'s doors).
    pub(crate) fn is_document_birth(&self) -> bool {
        self.made_by.process.identity.starts_with("entity_doc.")
    }

    /// The input hash over `parts`, each length-prefixed so two splits of the
    /// same bytes never collide.
    #[must_use]
    pub fn content_hash_of(parts: &[&[u8]]) -> String {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron made_by content_hash v1");
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        hasher.finalize().to_hex().to_string()
    }

    /// The shape rules a birth must meet before any row is read: a valid
    /// process, a hex input hash, well-formed withheld handles, and a prompt
    /// input on every triggered birth (the same rule `RowProvenance::fold`
    /// applies to a birth commit). A concluded birth names what it was made
    /// from, but for a room's: it keeps the evidence its caller supplied,
    /// none of which the room may have read as a TURN (FIX 4281). No count
    /// of inputs or handles is refused.
    pub(crate) fn check_shape(&self) -> Result<()> {
        let made_by = &self.made_by;
        let withheld = |role: WithheldRole| self.withheld.iter().any(|w| w.role == role);
        let has_prompt = made_by
            .inputs
            .iter()
            .any(|input| input.role == MadeByInputRole::Prompt)
            || withheld(WithheldRole::Prompt);
        let names_trigger = made_by.trigger.is_some() || withheld(WithheldRole::Trigger);
        let names_input = !made_by.inputs.is_empty()
            || withheld(WithheldRole::Input)
            || withheld(WithheldRole::Prompt);
        let handles_ok = self.withheld.iter().all(|w| {
            w.handle.strip_prefix("wh_").is_some_and(|hex| {
                hex.len() == WITHHELD_HANDLE_HEX
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        });
        let hash_ok = self.content_hash.len() <= MAX_CONTENT_HASH_HEX
            && self
                .content_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !made_by.process.is_valid()
            || !hash_ok
            || !handles_ok
            || (names_trigger && !has_prompt)
            || (made_by.process.class == MadeByClass::Concluded
                && !names_input
                && self.room_evidence.is_none())
        {
            return Err(Error::InvalidConfig(
                "a row birth needs a valid process, a hex input hash, well-formed withheld handles \
                 and a prompt input when it names a trigger"
                    .into(),
            ));
        }
        Ok(())
    }

    /// This birth as a base stamp takes it: a room's evidence stripped, so a
    /// marker a guest supplied counts for nothing outside a room (FIX 4281).
    pub(crate) fn base_form(&self) -> std::borrow::Cow<'_, Self> {
        if self.room_evidence.is_none() {
            return std::borrow::Cow::Borrowed(self);
        }
        let mut birth = self.clone();
        birth.room_evidence = None;
        std::borrow::Cow::Owned(birth)
    }
}

/// The vault's local secret behind [`WithheldKey::for_destination`]. Key:
/// `()`; value: 32 raw bytes. Local only: no copy or sync ships it.
const WITHHELD_SECRET: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::PROVENANCE_WITHHELD_SECRET);

/// One evidence ref a room write's caller supplied: as spelled, and the
/// TURN the caller read it as in the room with the bytes it read, when it
/// read one.
pub(crate) struct SuppliedEvidence {
    pub(crate) supplied: String,
    pub(crate) turn: Option<(EntityId, Vec<u8>)>,
}

impl RowBirth {
    /// The birth of a row `actor` staged in a room through `door` at `at`, of
    /// `class`, made from `inputs` (rows it derives from, with their bytes as
    /// read) and naming `evidence` as its caller supplied it. Each evidence
    /// ref the caller read as a TURN is an input too, hashed as read; each
    /// other ref is kept as supplied. A concluded birth that names no input
    /// is kept: the room never refuses a write for its evidence.
    pub(crate) fn in_room(
        actor: WriteActor,
        class: MadeByClass,
        door: &str,
        inputs: &[(EntityId, Vec<u8>)],
        evidence: &[SuppliedEvidence],
        at: u64,
    ) -> Self {
        let mut seen = std::collections::BTreeSet::new();
        let mut named = Vec::new();
        let mut read: Vec<&[u8]> = Vec::new();
        let supported = evidence
            .iter()
            .filter_map(|supplied| supplied.turn.as_ref());
        for (row, bytes) in inputs.iter().chain(supported) {
            if seen.insert(*row) {
                named.push(MadeByInput {
                    row: *row,
                    role: MadeByInputRole::Input,
                });
                read.push(bytes);
            }
        }
        let refs = evidence
            .iter()
            .map(|supplied| RoomEvidenceRef {
                supplied: supplied.supplied.clone(),
                turn: supplied.turn.as_ref().map(|(turn, _)| turn.to_hex()),
            })
            .collect();
        Self {
            made_by: MadeBy {
                inputs: named,
                process: MadeByProcess {
                    actor: actor.entity_ref(),
                    class,
                    identity: door.to_owned(),
                    version: "1".into(),
                    // A write door takes no render parameters.
                    params_hash: format!("{:x}", Sha256::digest([])),
                },
                at,
                trigger: None,
            },
            content_hash: if read.is_empty() {
                String::new()
            } else {
                Self::content_hash_of(&read)
            },
            withheld: Vec::new(),
            room_evidence: Some(RoomEvidence { refs }),
        }
    }
}

impl RowBirth {
    /// The birth of a row `actor` wrote through `door` at `at`, made of a
    /// model's answer to a prompt that carried the rows `prompt` (each named
    /// once, in order), whose bytes as the model read them are `read`.
    /// `None` when the prompt carried no row: the row keeps the birth its
    /// writer gives it.
    pub(crate) fn prompted(
        actor: WriteActor,
        class: MadeByClass,
        door: &str,
        prompt: &[EntityId],
        read: &[&[u8]],
        at: u64,
    ) -> Option<Self> {
        if prompt.is_empty() {
            return None;
        }
        let mut birth = Self::written(actor, class, door, prompt, read, at)?;
        for input in &mut birth.made_by.inputs {
            input.role = MadeByInputRole::Prompt;
        }
        Some(birth)
    }
}
