//! What a selector answer is made under, so the socket that queued it can
//! judge it again where it leaves (SELECTOR-RELEASE-POINT = B, a lead
//! ruling, Sun 15 Nov 19:26). ARCH-0077: "Revocation is not rollback. Queued
//! work follows the current Grant decision".
//!
//! The basis is the grant decision's inputs, read in one snapshot:
//! - the grant's live stored bytes, while the grant confers read at the
//!   second they are read: a delegate past its expiry has no basis, as the
//!   selector door refuses it (ONE-1409);
//! - the authority fold the selector door reads (pacts, their bindings and
//!   ceilings), from the snapshot-bound view, so a read takes no writer;
//! - the reach the grant's member reads relationship labels with (FIX
//!   SELECTOR-RELATIONSHIP-LABELS): its live access grants and relationship
//!   memberships, or none for an Owner's member, who reads every row. An
//!   access grant is stored outside the authority log, so the fold does not
//!   show its revocation or expiry;
//! - for a forwarded search, the reach of the caller it reads for
//!   ([`SelectorReaderReach`]): the caller's own access grants decide what it
//!   reads, beside the selector's ceiling. Its credential's standing is the
//!   fold's;
//! - the coreference disclosure the answer's filters decided
//!   ([`CoreferenceDisclosure`], SELECTOR-RELEASE-COREFERENCE-CONSENT = A,
//!   an Engine ruling, Sun 15 Nov 22:23): each `same_as` link its rows were
//!   let carry, with each export pact whose share consent let it. A consent
//!   is a claim row, not authority: the fold shows neither its retraction,
//!   nor an unlink, nor the end of its valid time.
//!
//! Each reach is read on the authorization clock every access decision
//! reads, observed first, so a grant past its expiry is not loaded. Each
//! share is judged on the policy clock the filter judged it on.
//!
//! A basis stands while a fresh read equals it, and while each share it
//! disclosed still holds. The rows an answer carries are content, not
//! authority, and are not compared: an unrelated write never drops an
//! answer, and neither does a consent given after it was made.

use std::cell::RefCell;
use std::collections::BTreeSet;

use crate::Vault;
use crate::access_grant::AccessContextSnapshot;
use crate::authority::AuthorityView;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{COREFERENCE_PACT_ID_LEN, ScopedReadActorKey};
use crate::entity_id::EntityId;
use crate::federation::{
    coreference_shared_for_pact_in_txn, decode_federation_grant_body, live_federation_grant_in,
};

/// What a selector answer under one grant was made under.
pub struct SelectorReleaseBasis {
    grant_id: EntityId,
    /// `None` when the grant was gone or conferred no read, or a read
    /// failed: such a basis never stands.
    made_under: Option<MadeUnder>,
    /// The reach of the forwarded caller the answer was read for, if any.
    reader: Option<SelectorReaderReach>,
    /// The coreference links the answer's rows were let carry.
    coreference: CoreferenceDisclosure,
}

impl SelectorReleaseBasis {
    /// The basis of an answer under the grant `grant_id`, read now.
    #[must_use]
    pub fn take(vault: &Vault, grant_id: EntityId) -> Self {
        Self {
            made_under: MadeUnder::read(vault, &grant_id),
            grant_id,
            reader: None,
            coreference: CoreferenceDisclosure::default(),
        }
    }

    /// The basis of an answer read for the forwarded caller whose reach
    /// `reader` holds, taken before that read: the answer stands only while
    /// that reach does too.
    #[must_use]
    pub fn reading_for(mut self, reader: Option<SelectorReaderReach>) -> Self {
        self.reader = reader;
        self
    }

    /// The basis of an answer whose filters decided `disclosure`: the
    /// answer stands only while each link it was let carry is still shared
    /// into its pact.
    #[must_use]
    pub fn disclosing(mut self, disclosure: CoreferenceDisclosure) -> Self {
        self.coreference.shares.extend(disclosure.shares);
        self
    }

    /// The grant the answer is made under.
    #[must_use]
    pub fn grant_id(&self) -> &EntityId {
        &self.grant_id
    }

    /// Whether what the answer was made under stands now: the grant still
    /// confers read, its bytes, the authority fold, its member's reach and a
    /// forwarded caller's reach read as they did, and each coreference link
    /// it was let carry is still shared into its pact.
    #[must_use]
    pub fn stands(&self, vault: &Vault) -> bool {
        self.made_under.as_ref().is_some_and(|made_under| {
            MadeUnder::read(vault, &self.grant_id).is_some_and(|now| now.same(made_under))
        }) && self
            .reader
            .as_ref()
            .is_none_or(|reader| reader.stands(vault))
            && self.coreference.stands(vault)
    }
}

/// One coreference share: a `same_as` link, endpoints in a stable order, and
/// an export pact the owner consented to share it into.
pub(super) type CoreferenceShare = ((EntityId, EntityId), [u8; COREFERENCE_PACT_ID_LEN]);

/// The coreference disclosure a selector answer's filters decided: each
/// `same_as` link they let its rows carry (the link edge, and its status and
/// share-consent claims), with each export pact whose share consent let it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreferenceDisclosure {
    shares: BTreeSet<CoreferenceShare>,
}

thread_local! {
    /// The disclosure recording open on this thread, if any.
    static RECORDING: RefCell<Option<CoreferenceDisclosure>> = const { RefCell::new(None) };
}

/// Runs `answer`, and returns beside what it returned the coreference
/// disclosure each selector filter run meanwhile on this thread decided,
/// with each disclosure recorded through [`CoreferenceDisclosure::record`].
/// An answer's filters run on the thread that makes it. An enclosing
/// recording is put back after, panic or not, and also receives these
/// shares: its answer carries these rows too.
#[must_use]
pub fn recording_coreference_disclosure<T>(
    answer: impl FnOnce() -> T,
) -> (T, CoreferenceDisclosure) {
    struct Restore(Option<CoreferenceDisclosure>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let enclosing = self.0.take();
            RECORDING.with(|slot| *slot.borrow_mut() = enclosing);
        }
    }
    let restore =
        Restore(RECORDING.with(|slot| slot.replace(Some(CoreferenceDisclosure::default()))));
    let done = answer();
    let disclosed = RECORDING
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default();
    drop(restore);
    disclosed.record();
    (done, disclosed)
}

/// Adds `shares` to the recording open on this thread, if any.
pub(super) fn record_coreference_shares(shares: impl IntoIterator<Item = CoreferenceShare>) {
    RECORDING.with(|slot| {
        if let Some(open) = slot.borrow_mut().as_mut() {
            open.shares.extend(shares);
        }
    });
}

impl CoreferenceDisclosure {
    /// Records this disclosure again into the recording open on this
    /// thread, for an answer that carries rows an earlier filter decided
    /// (a retained residence index's later page).
    pub fn record(&self) {
        if !self.shares.is_empty() {
            record_coreference_shares(self.shares.iter().copied());
        }
    }

    /// Whether each share still holds now: the link is stored, its people
    /// are people, and a live, approved share consent names the pact at the
    /// policy clock's second, as the filter judged it.
    fn stands(&self, vault: &Vault) -> bool {
        if self.shares.is_empty() {
            return true;
        }
        let now = vault.now_recorded_at();
        let Ok(txn) = vault.store.env.read_txn() else {
            return false;
        };
        self.shares.iter().all(|((a, b), pact_id)| {
            matches!(
                coreference_shared_for_pact_in_txn(vault, &txn, *a, *b, pact_id, now),
                Ok(true)
            )
        })
    }
}

/// The reach of the caller a forwarded search reads for: its own live
/// access grants and relationship memberships, which decide what it reads
/// beside the selector's ceiling.
pub struct SelectorReaderReach {
    principal: EntityId,
    /// `None` when the read failed: such a reach never stands.
    reach: Option<AccessContextSnapshot>,
}

impl SelectorReaderReach {
    /// The reach a read under `reader` loads, read now; `None` for a reader
    /// that loads no principal's grants.
    #[must_use]
    pub fn take(vault: &Vault, reader: &ScopedReadActorKey) -> Option<Self> {
        let principal = reader.access_principal()?;
        Some(Self {
            principal,
            reach: read_reach(vault, principal),
        })
    }

    fn stands(&self, vault: &Vault) -> bool {
        self.reach.as_ref().is_some_and(|reach| {
            read_reach(vault, self.principal).is_some_and(|now| now.same_reach(reach))
        })
    }
}

/// The reach of `principal`, read now on the authorization clock, observed
/// first as [`Vault::access_context`] observes it.
fn read_reach(vault: &Vault, principal: EntityId) -> Option<AccessContextSnapshot> {
    vault.store.authorization_now().ok()?;
    let txn = vault.store.env.read_txn().ok()?;
    AccessContextSnapshot::load(vault, &txn, Some(principal)).ok()
}

struct MadeUnder {
    grant: Vec<u8>,
    authority: AuthorityView,
    /// `None` for an Owner's member, which reads every row.
    member: Option<AccessContextSnapshot>,
}

impl MadeUnder {
    fn read(vault: &Vault, grant_id: &EntityId) -> Option<Self> {
        // The second the selector door judges expiry at, read before its
        // snapshot as the door reads it.
        let now = vault.now_recorded_at();
        // The member's reach is read on the authorization clock, observed
        // first as every access decision observes it: a grant past its
        // expiry is not loaded once the clock's lease has lapsed.
        vault.store.authorization_now().ok()?;
        let txn = vault.store.env.read_txn().ok()?;
        let grant = live_federation_grant_in(vault, &txn, grant_id).ok()?;
        let decoded =
            decode_federation_grant_body(grant.get(ENTITY_METADATA_HEADER_LEN..)?).ok()?;
        if !decoded.confers_at(now) {
            return None;
        }
        Some(Self {
            authority: vault.authority_view_readonly_in_txn(&txn).ok()?,
            member: super::authorize::member_label_access(vault, &txn, &decoded)
                .ok()?
                .map(|access| access.snapshot().clone()),
            grant,
        })
    }

    fn same(&self, other: &Self) -> bool {
        self.grant == other.grant
            && self.authority.same_image(&other.authority)
            && match (&self.member, &other.member) {
                (None, None) => true,
                (Some(member), Some(other)) => member.same_reach(other),
                _ => false,
            }
    }
}
