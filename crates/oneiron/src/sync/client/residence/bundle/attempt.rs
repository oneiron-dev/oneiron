//! The exact attempt this install makes to publish the vault's sealed bundle,
//! asked or automatic (FIX 4787, FIX 9254, CALLS BUNDLE_PUBLISH_RECONCILE).
//! Before its first commit send the executor persists the attempt under one
//! durable key per logical pending request or dialed route address: the
//! exact input (generation, parent, root, request), both objects' lengths
//! and ciphertext digests, the home it knew, if any, and itself, and the
//! report metadata a resumed commit replays. A later pass reconciles the
//! saved attempt against the home's work status (see `super::work`) instead
//! of reassembling: a finished exact attempt commits, a pending or
//! unanswered one stays uncertain, and only a genuine refusal or rebase
//! settles the exact attempt and frees a retry. The saved home is a binding
//! hint only; resume keys by request or route address, so proof flapping
//! between unknown and known never orphans an attempt. Sealed metadata
//! only, never bundle bytes; the one attempt table, no expiry, no count
//! bound, no second ledger.

use crate::Vault;
use crate::authority::AuthorityEntryHash;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result, SyncProtocolValidation};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::residence::{SealedBundleCommitInput, sealed_digest_from_hex, sealed_digest_hex};
use crate::world_keys::{RecoveryRootId, SealedBundleGeneration, UnmergedSection, UnmergedStage};

/// This install's unresolved attempts: request hex for asked ones, `auto:`
/// plus the route address digest hex for automatic ones.
const ATTEMPTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_ATTEMPT);

/// Automatic keys carry this prefix, so they never parse as a request hash
/// and the request-result sweep below skips them; an automatic attempt
/// settles explicitly on its terminal outcome. The address after it is the
/// dialed endpoint's route digest, never a machine: one durable attempt per
/// route, whether the home's proof stands here or not.
const AUTO_PREFIX: &str = "auto:";

/// The fixed header: home?1 ‖ home16 ‖ executor16 ‖ generation24 ‖ parent?1 ‖
/// parent24 ‖ root?1 ‖ root32 ‖ request?1 ‖ request32 ‖ bundleTotal8 ‖
/// bundleDigest32 ‖ padsTotal8 ‖ padsDigest32. Absent options zero their
/// bytes; the flags rule. Two u64be-counted [`EntityId`] tails follow: the
/// incomplete authorities, then the awaiting readers. A third, u64be-counted
/// tail of unmerged sections follows only when it lists one (FIX 19525), so a
/// row with none is byte for byte the row written before it existed: each
/// section is world16 ‖ stage1 ‖ window?1 ‖ (windowLen u32be ‖ window) ‖
/// kindLen u16be ‖ kind, the kind its snake_case wire name.
const ATTEMPT_FIXED_LEN: usize = 1 + 16 + 16 + 24 + 1 + 24 + 1 + 32 + 1 + 32 + 8 + 32 + 8 + 32;

/// Which logical attempt a row is: one per pending owner request, or one per
/// dialed route address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AttemptKey {
    Request(AuthorityEntryHash),
    Auto([u8; 32]),
}

impl AttemptKey {
    fn encode(&self) -> String {
        match self {
            Self::Request(request) => sealed_digest_hex(request),
            Self::Auto(address) => format!("{AUTO_PREFIX}{}", sealed_digest_hex(address)),
        }
    }
}

/// One attempt, as persisted before its first commit send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleAttempt {
    /// The home this install believed it reached, when its proof stood here;
    /// `None` when unknown. A binding hint only, never identity: resume keys
    /// by request or route address.
    pub(crate) home: Option<EntityId>,
    pub(crate) executor: EntityId,
    pub(crate) generation: SealedBundleGeneration,
    /// BLAKE3 of the sealed bundle's bytes.
    pub(crate) bundle_digest: [u8; 32],
    pub(super) parent: Option<SealedBundleGeneration>,
    pub(super) root: Option<RecoveryRootId>,
    pub(super) request: Option<AuthorityEntryHash>,
    pub(super) bundle_total: u64,
    pub(super) pads_total: u64,
    /// BLAKE3 of the sealed pad object's bytes.
    pub(super) pads_digest: [u8; 32],
    /// Each world whose capsule the upload does not seal fresh (FIX 4497),
    /// kept so a resumed commit reports what the sealing pass saw.
    pub(super) incomplete_authority: Vec<EntityId>,
    /// Each world a kit restore of the upload awaits a reader for (FIX
    /// 4496).
    pub(super) awaiting_reader: Vec<EntityId>,
    /// Each readable section the upload carries unchanged because it did not
    /// open, decode or merge here (FIX 19525), kept so a commit a later pass
    /// finds, after a lost acknowledgement or a restart, still shows it to
    /// the owner. A row written without it carries none.
    pub(super) unmerged_sections: Vec<UnmergedSection>,
    /// When this install assembled the upload (FIX 19525): its recorded
    /// clock seconds, raised at persist above every attempt still stored, so
    /// no two coexisting attempts share one and a later assembly is always
    /// greater. The order in which reconciled attempts' sections are shown,
    /// newest last. `None` for a row written before it was kept.
    pub(super) assembled_at: Option<u64>,
}

impl BundleAttempt {
    /// The exact commit input this attempt sends, fresh or resent.
    pub(super) fn input(&self) -> SealedBundleCommitInput {
        SealedBundleCommitInput {
            generation: self.generation,
            parent: self.parent,
            root: self.root,
            request: self.request,
        }
    }

    /// Both objects' lengths and ciphertext digests, bundle first.
    pub(super) fn objects(&self) -> [(u64, [u8; 32]); 2] {
        [
            (self.bundle_total, self.bundle_digest),
            (self.pads_total, self.pads_digest),
        ]
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            ATTEMPT_FIXED_LEN
                + 16
                + 16 * (self.incomplete_authority.len() + self.awaiting_reader.len()),
        );
        match self.home {
            Some(home) => {
                out.push(1);
                out.extend_from_slice(home.as_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 16]);
            }
        }
        out.extend_from_slice(self.executor.as_bytes());
        out.extend_from_slice(&self.generation.to_bytes());
        match self.parent {
            Some(parent) => {
                out.push(1);
                out.extend_from_slice(&parent.to_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 24]);
            }
        }
        match self.root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(&root.0);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        match self.request {
            Some(request) => {
                out.push(1);
                out.extend_from_slice(&request);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        out.extend_from_slice(&self.bundle_total.to_be_bytes());
        out.extend_from_slice(&self.bundle_digest);
        out.extend_from_slice(&self.pads_total.to_be_bytes());
        out.extend_from_slice(&self.pads_digest);
        for worlds in [&self.incomplete_authority, &self.awaiting_reader] {
            out.extend_from_slice(&(worlds.len() as u64).to_be_bytes());
            for world in worlds.iter() {
                out.extend_from_slice(world.as_bytes());
            }
        }
        // The third tail (FIX 19525): when the upload was assembled, then
        // its unmerged sections. A row written before it was kept has none,
        // and encodes byte for byte as it was stored.
        if self.assembled_at.is_some() || !self.unmerged_sections.is_empty() {
            out.extend_from_slice(&self.assembled_at.unwrap_or_default().to_be_bytes());
            out.extend_from_slice(&(self.unmerged_sections.len() as u64).to_be_bytes());
            for section in &self.unmerged_sections {
                encode_unmerged(&mut out, section)?;
            }
        }
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < ATTEMPT_FIXED_LEN {
            return Err(Error::InvalidKey);
        }
        let id = |range: std::ops::Range<usize>| -> Result<EntityId> {
            let bytes: [u8; 16] = raw[range].try_into().map_err(|_| Error::InvalidKey)?;
            EntityId::from_bytes(bytes).map_err(|_| Error::InvalidKey)
        };
        let flag = |at: usize| -> Result<bool> {
            match raw[at] {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(Error::InvalidKey),
            }
        };
        let be_u64 = |range: std::ops::Range<usize>| -> Result<u64> {
            Ok(u64::from_be_bytes(
                raw[range].try_into().map_err(|_| Error::InvalidKey)?,
            ))
        };
        let home = if flag(0)? { Some(id(1..17)?) } else { None };
        let parent = if flag(57)? {
            Some(SealedBundleGeneration::from_bytes(&raw[58..82])?)
        } else {
            None
        };
        let root = if flag(82)? {
            Some(RecoveryRootId(
                raw[83..115].try_into().map_err(|_| Error::InvalidKey)?,
            ))
        } else {
            None
        };
        let request = if flag(115)? {
            Some(raw[116..148].try_into().map_err(|_| Error::InvalidKey)?)
        } else {
            None
        };
        let mut at = ATTEMPT_FIXED_LEN;
        let mut tails = [Vec::new(), Vec::new()];
        for tail in tails.iter_mut() {
            let head = at.checked_add(8).ok_or(Error::InvalidKey)?;
            let count = raw.get(at..head).ok_or(Error::InvalidKey)?;
            let count = u64::from_be_bytes(count.try_into().map_err(|_| Error::InvalidKey)?);
            let len = usize::try_from(count)
                .ok()
                .and_then(|count| count.checked_mul(16))
                .ok_or(Error::InvalidKey)?;
            let end = head.checked_add(len).ok_or(Error::InvalidKey)?;
            let words = raw.get(head..end).ok_or(Error::InvalidKey)?;
            for word in words.chunks_exact(16) {
                let word: [u8; 16] = word.try_into().map_err(|_| Error::InvalidKey)?;
                tail.push(EntityId::from_bytes(word).map_err(|_| Error::InvalidKey)?);
            }
            at = end;
        }
        let (assembled_at, unmerged_sections) = if at == raw.len() {
            (None, Vec::new())
        } else {
            let assembled_at = u64::from_be_bytes(
                read_at(raw, &mut at, 8)?
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            );
            (Some(assembled_at), decode_unmerged(raw, &mut at)?)
        };
        if at != raw.len() {
            return Err(Error::InvalidKey);
        }
        let [incomplete_authority, awaiting_reader] = tails;
        Ok(Self {
            home,
            executor: id(17..33)?,
            generation: SealedBundleGeneration::from_bytes(&raw[33..57])?,
            bundle_digest: raw[156..188].try_into().map_err(|_| Error::InvalidKey)?,
            parent,
            root,
            request,
            bundle_total: be_u64(148..156)?,
            pads_total: be_u64(188..196)?,
            pads_digest: raw[196..228].try_into().map_err(|_| Error::InvalidKey)?,
            incomplete_authority,
            awaiting_reader,
            unmerged_sections,
            assembled_at,
        })
    }
}

/// The byte `stage` is stored as.
const fn stage_byte(stage: UnmergedStage) -> u8 {
    match stage {
        UnmergedStage::Open => 0,
        UnmergedStage::Decode => 1,
        UnmergedStage::Merge => 2,
    }
}

/// Appends one unmerged section of the third tail (FIX 19525).
fn encode_unmerged(out: &mut Vec<u8>, section: &UnmergedSection) -> Result<()> {
    out.extend_from_slice(section.world.as_bytes());
    out.push(stage_byte(section.stage));
    match &section.window {
        Some(window) => {
            let len = u32::try_from(window.len()).map_err(|_| Error::InvalidKey)?;
            out.push(1);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(window.as_bytes());
        }
        None => out.push(0),
    }
    let Ok(serde_json::Value::String(kind)) = serde_json::to_value(section.kind) else {
        return Err(Error::InvalidKey);
    };
    let len = u16::try_from(kind.len()).map_err(|_| Error::InvalidKey)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(kind.as_bytes());
    Ok(())
}

/// The `len` bytes of `raw` at `at`, which then moves past them.
fn read_at<'a>(raw: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = at.checked_add(len).ok_or(Error::InvalidKey)?;
    let bytes = raw.get(*at..end).ok_or(Error::InvalidKey)?;
    *at = end;
    Ok(bytes)
}

/// Reads the unmerged sections of the third tail at `at` (FIX 19525), none
/// or more.
fn decode_unmerged(raw: &[u8], at: &mut usize) -> Result<Vec<UnmergedSection>> {
    let count = u64::from_be_bytes(
        read_at(raw, at, 8)?
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
    );
    let mut sections = Vec::new();
    for _ in 0..count {
        let world: [u8; 16] = read_at(raw, at, 16)?
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let world = EntityId::from_bytes(world).map_err(|_| Error::InvalidKey)?;
        let stage = match read_at(raw, at, 1)?[0] {
            0 => UnmergedStage::Open,
            1 => UnmergedStage::Decode,
            2 => UnmergedStage::Merge,
            _ => return Err(Error::InvalidKey),
        };
        let window = match read_at(raw, at, 1)?[0] {
            0 => None,
            1 => {
                let len = u32::from_be_bytes(
                    read_at(raw, at, 4)?
                        .try_into()
                        .map_err(|_| Error::InvalidKey)?,
                );
                let len = usize::try_from(len).map_err(|_| Error::InvalidKey)?;
                let window = read_at(raw, at, len)?.to_vec();
                Some(String::from_utf8(window).map_err(|_| Error::InvalidKey)?)
            }
            _ => return Err(Error::InvalidKey),
        };
        let len = u16::from_be_bytes(
            read_at(raw, at, 2)?
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        let kind = String::from_utf8(read_at(raw, at, usize::from(len))?.to_vec())
            .map_err(|_| Error::InvalidKey)?;
        let kind: ErrorKind = serde_json::from_value(serde_json::Value::String(kind))
            .map_err(|_| Error::InvalidKey)?;
        sections.push(UnmergedSection {
            world,
            window,
            stage,
            kind,
        });
    }
    Ok(sections)
}

/// Persists this install's exact attempt under `key`. The caller resolved
/// every field, including the executor, which is never invented here. A
/// different still-unresolved attempt under the key is never overwritten:
/// the write fails and the caller keeps the old attempt. Identical bytes
/// persist idempotently.
///
/// A fresh attempt's assembly time is raised, in the same writer, above
/// every attempt still stored (FIX 19525), and `attempt` takes the value
/// stored, so its later compares meet the stored bytes.
pub(super) fn persist(vault: &Vault, key: AttemptKey, attempt: &mut BundleAttempt) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        let current = ATTEMPTS.get_bytes(&vault.store, wtxn, &key.encode())?;
        if let Some(current) = current {
            if current != attempt.encode()? {
                return Err(Error::sync_protocol(
                    SyncProtocolValidation::DocumentPendingUpdate,
                ));
            }
            return Ok(());
        }
        if let Some(assembled_at) = attempt.assembled_at {
            let mut order = assembled_at;
            for row in ATTEMPTS.iter_raw_from(&vault.store, wtxn, &[])? {
                let (_, raw) = row?;
                if let Ok(stored) = BundleAttempt::decode(&raw)
                    && let Some(stored_at) = stored.assembled_at
                {
                    order = order.max(stored_at.saturating_add(1));
                }
            }
            attempt.assembled_at = Some(order);
        }
        ATTEMPTS.put(&vault.store, wtxn, &key.encode(), &attempt.encode()?)
    })
}

/// Forgets the exact attempt under `key` when `expected` is still current:
/// its terminal outcome settled it. A missing row, or one already another
/// attempt, stays: a stale reply never deletes a newer attempt. The compare
/// and the delete share the one writer.
pub(super) fn settle_one(vault: &Vault, key: AttemptKey, expected: &BundleAttempt) -> Result<()> {
    let encoded = expected.encode()?;
    vault.with_write_txn_grouped(|wtxn| {
        let current = ATTEMPTS.get_bytes(&vault.store, wtxn, &key.encode())?;
        if current.as_deref() == Some(encoded.as_slice()) {
            ATTEMPTS.delete(&vault.store, wtxn, &key.encode())?;
        }
        Ok(())
    })
}

/// Forgets every asked attempt whose request has its result here: it is
/// resolved. Rows that do not parse as a request, and requests still
/// unresolved, stay.
pub(super) fn settle(vault: &Vault) -> Result<()> {
    let resolved: Vec<String> = {
        let txn = vault.store.env.read_txn()?;
        let fold = vault.authority_view_readonly_in_txn(&txn)?;
        let mut resolved = Vec::new();
        for row in ATTEMPTS.iter_raw_from(&vault.store, &txn, &[])? {
            let (key, _) = row?;
            let Ok(key) = String::from_utf8(key) else {
                continue;
            };
            if sealed_digest_from_hex(&key)
                .is_some_and(|request| fold.owner_work_result(&request).is_some())
            {
                resolved.push(key);
            }
        }
        resolved
    };
    if resolved.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for key in &resolved {
            ATTEMPTS.delete(&vault.store, wtxn, key)?;
        }
        Ok(())
    })
}

impl Vault {
    /// The attempt this install persisted for the bundle publication
    /// `request` and has not resolved, when it is this install's (FIX 4787):
    /// `None` with none, or with one another machine id persisted here.
    /// Bytes that do not decode are an error, never an open retry: a corrupt
    /// current-format row stays uncertain, it does not free another upload.
    pub(crate) fn unresolved_bundle_attempt(
        &self,
        request: AuthorityEntryHash,
    ) -> Result<Option<BundleAttempt>> {
        Self::unresolved_attempt(self, &AttemptKey::Request(request))
    }

    /// The automatic attempt this install persisted for the route `address`
    /// and has not resolved, when it is this install's (FIX 9254): `None`
    /// with none, or with one another machine id persisted here. Bytes that
    /// do not decode are an error, never an open retry.
    pub(super) fn unresolved_auto_attempt(
        &self,
        address: [u8; 32],
    ) -> Result<Option<BundleAttempt>> {
        Self::unresolved_attempt(self, &AttemptKey::Auto(address))
    }

    fn unresolved_attempt(&self, key: &AttemptKey) -> Result<Option<BundleAttempt>> {
        let txn = self.store.env.read_txn()?;
        let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
        Ok(ATTEMPTS
            .get_bytes(&self.store, &txn, &key.encode())?
            .map(|raw| BundleAttempt::decode(&raw))
            .transpose()?
            .filter(|attempt| Some(attempt.executor) == me))
    }
}
