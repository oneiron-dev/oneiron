//! Doors for `tests/claim_source_recheck_decide.rs` (DECIDE-BYPASS-1): seed one
//! provider-deleted, kept mail message with one live claim on it, run the
//! re-check, and read the finding back. Thin wrappers over production APIs
//! only; no judge logic here. Compiled only under `--cfg oneiron_test_support`
//! (`test_doors`); hidden, never API.

use std::cell::RefCell;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{
    BudgetGuard, CallPurpose, HostInferenceBinding, HostInferenceContext, LlmBackend, LlmRequest,
    ModelId, ModelLocality,
};
use crate::mail_pack::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryChange,
    MailHistoryPage, MailHistoryRead, MailIdPage, MailListQuery, MailMessageRef, MailProvider,
    MailProviderWire, MailSourceConnectRequest, MailSourceKind, MailSyncBudget, MailSyncSource,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::{DreamerAdmittedAttempt, DreamerAttemptExecution, WakeAttemptContext};

pub use crate::model_decision::catalogue::CLAIM_SOURCE_SUPPORT;

/// What [`seed`] leaves for the test: the live claim and its admitted
/// re-check attempt.
#[doc(hidden)]
pub struct SeededRecheck {
    pub claim: EntityId,
    pub attempt: DreamerAdmittedAttempt,
}

/// The provider id the seeded message carries.
const SEED_PROVIDER_ID: &str = "msg-1";

/// The custody name the seeded credential is stored under.
const SEED_CUSTODY_REF: &str = "test-mail-cred";

/// The seeded source's mailbox address and provider account.
const SEED_ADDRESS: &str = "owner@test.example";
const SEED_ACCOUNT: &str = "test-account";

/// The seeded message's words.
const SEED_BODY: &str = "The project deadline is Friday.";

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

fn memory_invalid(where_: &str, error: crate::memory::MemoryError) -> Error {
    invalid(&format!("{where_}: {}: {}", error.code, error.message))
}

/// The seeded message's headers at `received_at`.
fn seed_headers(received_at: u64) -> MailHeaders {
    MailHeaders {
        provider_id: SEED_PROVIDER_ID.to_owned(),
        thread_id: Some("thread-1".to_owned()),
        rfc_message_id: Some("<msg-1@test>".to_owned()),
        in_reply_to: None,
        references: Vec::new(),
        from: Some("alice@test.example".to_owned()),
        to: vec![SEED_ADDRESS.to_owned()],
        cc: Vec::new(),
        reply_to: Vec::new(),
        subject: Some("Test message".to_owned()),
        date: Some(received_at),
        received_at,
        labels: vec!["INBOX".to_owned()],
        sent_by_mailbox: false,
        trash_or_spam: false,
        draft: false,
    }
}

/// The seeded message read whole.
fn seed_full(received_at: u64) -> MailFull {
    MailFull {
        headers: seed_headers(received_at),
        body_text: Some(SEED_BODY.to_owned()),
        attachments: Vec::new(),
        content_digest: None,
    }
}

/// The fake provider wire [`seed`] imports and deletes through: it lists the
/// one seeded message until [`SeedMailWire::set_deleted`], then reports it
/// deleted at the provider and lists nothing.
struct SeedMailWire {
    headers: MailHeaders,
    full: MailFull,
    deleted: RefCell<bool>,
}

impl SeedMailWire {
    fn new(received_at: u64) -> Self {
        Self {
            headers: seed_headers(received_at),
            full: seed_full(received_at),
            deleted: RefCell::new(false),
        }
    }

    fn set_deleted(&self) {
        *self.deleted.borrow_mut() = true;
    }

    fn is_deleted(&self) -> bool {
        *self.deleted.borrow()
    }
}

impl MailProviderWire for SeedMailWire {
    fn current_anchor(&self, _source: &MailSyncSource) -> Result<String> {
        Ok("seed-anchor".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> Result<MailIdPage> {
        if self.is_deleted() {
            return Ok(MailIdPage {
                messages: Vec::new(),
                next_page: None,
            });
        }
        Ok(MailIdPage {
            messages: vec![MailMessageRef {
                provider_id: SEED_PROVIDER_ID.to_owned(),
                thread_id: Some("thread-1".to_owned()),
            }],
            next_page: None,
        })
    }

    fn headers(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        if self.is_deleted() || provider_id != SEED_PROVIDER_ID {
            return Ok(None);
        }
        Ok(Some(self.headers.clone()))
    }

    fn full(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        if self.is_deleted() || provider_id != SEED_PROVIDER_ID {
            return Ok(None);
        }
        Ok(Some(self.full.clone()))
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        _anchor: &str,
        _page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        let changes = if self.is_deleted() {
            vec![MailHistoryChange::Deleted {
                provider_id: SEED_PROVIDER_ID.to_owned(),
            }]
        } else {
            Vec::new()
        };
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes,
            next_page: None,
            anchor: "seed-anchor".to_owned(),
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn raw_address_headers(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
    ) -> Result<Option<MailAddressHeaders>> {
        Ok(None)
    }
}

/// Lets fixture extraction run on the own server, as the consolidation test
/// doors do: the extraction purpose's locality and bound are the own server.
fn allow_own_server_extraction(vault: &Vault) -> Result<()> {
    let mut policy = vault.purpose_default_table()?;
    policy.extraction_max_locality = ModelLocality::OwnServer;
    policy
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .ok_or_else(|| invalid("missing extraction row"))?
        .locality = ModelLocality::OwnServer;
    vault.set_purpose_default_table(&policy)
}

/// The egress verdict [`run`] lends its judge: the fixture allows it, as the
/// consolidation test doors do.
fn allow_recheck_extraction(_: &LlmRequest) -> bool {
    true
}

/// Seeds one mail source, one imported message, one live approved claim
/// citing its TURN, the kept provider delete that owes the re-check, and the
/// admitted maintenance attempt of facet
/// `dreamer.claim_source_recheck`. The Dreamer is added to the thread's
/// readers so the claim reads to its judge, and the seed refuses when it
/// does not.
///
/// # Errors
///
/// The vault's, or a seeded row the Dreamer may not read.
#[doc(hidden)]
pub fn seed(vault: &Vault, now_ms: u64) -> Result<SeededRecheck> {
    let now_sec = now_ms / 1_000;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| invalid(&format!("embedded owner: {error:?}")))?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    crate::mail_pack::install_mail_calendar_pack_embedded(&memory)
        .map_err(|error| memory_invalid("mail pack install", error))?;
    vault.register_secret(crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: SEED_CUSTODY_REF.to_owned(),
        class: crate::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        model_reveal_allowed: true,
        value_bytes: b"test-mail-token".to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: now_sec,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![crate::secret_custody::SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: crate::secret_custody::CustodyTier::T0Doored,
            scopes: Vec::new(),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    })?;
    let receipt = memory
        .mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Google,
            kind: MailSourceKind::PersonalMailbox,
            address: SEED_ADDRESS.to_owned(),
            provider_account: SEED_ACCOUNT.to_owned(),
            custody_ref: SEED_CUSTODY_REF.to_owned(),
            members: Vec::new(),
            for_person: None,
            channel_identity_ref: None,
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .map_err(|error| memory_invalid("mail connect", error))?;
    let source =
        EntityId::from_hex(&receipt.source.source_ref).map_err(|_| invalid("mail source ref"))?;
    let owner_proof = memory
        .embedded_owner("vault.mail.sources.sync")
        .map_err(|error| memory_invalid("owner proof", error))?;
    let wire = SeedMailWire::new(now_sec);
    vault
        .mail_sync_step(&owner_proof, source, &wire, MailSyncBudget::default())
        .map_err(|error| memory_invalid("mail import", error))?;
    let source_hex = source.to_hex();
    let turn = EntityId::derive(
        crate::entity_id::derived_domains::MAIL_TURN,
        &[source_hex.as_bytes(), SEED_PROVIDER_ID.as_bytes()],
    )?;
    allow_own_server_extraction(vault)?;
    let dreamer = vault.dreamer_authority()?.entity_ref();
    let policy = {
        let txn = vault.store.env.read_txn()?;
        crate::source_audience::binding_in(vault, &txn, &turn)?
            .ok_or_else(|| invalid("mail turn has no source policy"))?
    };
    vault.with_write_txn_grouped(|txn| {
        crate::source_audience::share_thread_in_txn(
            vault, txn, &policy, dreamer, true, owner, now_sec,
        )?;
        Ok(())
    })?;
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now_sec,
            end: now_sec,
        },
        now_sec,
        b"recheck subject",
    )?;
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("Ada Lovelace"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Generated);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    body.evidence = Some(crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![turn],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    ));
    vault.put_claim(
        &claim,
        &body,
        TimeRange {
            start: now_sec,
            end: now_sec,
        },
        now_sec,
    )?;
    {
        vault.store.authorization_now()?;
        let txn = vault.store.env.read_txn()?;
        let key = crate::claim::ScopedReadActorKey::with_actor_class(
            dreamer.to_hex(),
            EdgeActorClass::System.gate_actor_class(),
        )
        .ok_or_else(|| invalid("dreamer read key"))?;
        let reader = vault.scoped_read(key);
        if reader.entities_readable_in_txn(&txn, std::slice::from_ref(&claim))? != [true] {
            return Err(invalid("seeded claim is not readable by the Dreamer"));
        }
    }
    wire.set_deleted();
    vault
        .mail_sync_step(&owner_proof, source, &wire, MailSyncBudget::default())
        .map_err(|error| memory_invalid("mail provider delete", error))?;
    let store = DreamerRunnerStore::new(vault);
    let admitted = match store.admit_next_maintenance(AdmitDreamerAttempt {
        lease_owner: "claim-source-recheck-test".to_owned(),
        now: now_sec,
        budget_id: "wake".to_owned(),
        budget_total_units: 10_000,
        reserve_units: 100,
        started_milestone: None,
    })? {
        DreamerAdmissionOutcome::Admitted(admitted) => *admitted,
        _ => return Err(invalid("recheck attempt was not admitted")),
    };
    if admitted.status.payload.attempt_type
        != crate::dreamer_runner::maintenance::claim_source_recheck::CLAIM_SOURCE_RECHECK_FACET
    {
        return Err(invalid("admitted attempt is not a claim re-check"));
    }
    Ok(SeededRecheck {
        claim,
        attempt: admitted,
    })
}

/// Runs the admitted re-check with the host's judge route, rubric, and
/// decision path. Builds the [`HostInferenceContext`] (advertised own
/// server, fixture egress) and the re-check model, then calls
/// `run_claim_source_recheck`.
///
/// # Errors
///
/// The re-check's.
#[doc(hidden)]
pub async fn run(
    ctx: &WakeAttemptContext<'_>,
    attempt: &DreamerAdmittedAttempt,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    model: &ModelId,
    rubric: &str,
    ladder: crate::llm::decision::DecisionLadder<'_>,
    bands: crate::model_decision::DecisionBandPolicy,
    wording: &str,
) -> Result<DreamerAttemptExecution> {
    let inference = HostInferenceContext {
        binding: HostInferenceBinding::Advertised {
            model: model.clone(),
            locality: ModelLocality::OwnServer,
            keyless: false,
        },
        extraction_egress: Some(&allow_recheck_extraction),
    };
    let lent = crate::dreamer_runner::maintenance::claim_source_recheck::ClaimSourceRecheckModel {
        backend,
        guard,
        model: model.clone(),
        inference,
        role: crate::dreamer_consolidation::DREAMER_NARRATIVE_ROLE,
        rubric,
        decisions:
            crate::dreamer_runner::maintenance::claim_source_recheck::ClaimSourceRecheckDecisions {
                ladder,
                bands,
                wording: wording.to_owned(),
            },
    };
    crate::dreamer_runner::maintenance::claim_source_recheck::run_claim_source_recheck(
        attempt, ctx, lent,
    )
    .await
}

/// Reads back the finding the re-check landed for `claim`: the plain
/// `dreamer.claim_source_recheck.verdict` finding, or the curator rung's own
/// finding on a weakened or unsupported verdict. Answers its full value,
/// which carries `recheck`.
///
/// # Errors
///
/// The vault's, or no finding for the claim; that error counts the claim
/// rows it could not read or decode and names each claim about `claim`.
#[doc(hidden)]
pub fn finding(vault: &Vault, claim: EntityId) -> Result<serde_json::Value> {
    let wanted = [
        crate::dreamer_runner::maintenance::claim_source_recheck::CLAIM_SOURCE_RECHECK_PREDICATE,
        crate::dreamer_runner::maintenance::CURATOR_PROPOSAL_PREDICATE,
    ];
    let mut unreadable = 0_usize;
    let mut undecodable = 0_usize;
    let mut about_claim = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_CLAIM)? {
        // `Vault::get` answers the row's body, its metadata header already off.
        let Some(body) = vault.get(&id)? else {
            unreadable += 1;
            continue;
        };
        let Ok(decoded) = crate::claim::decode_claim_body(&body, true) else {
            undecodable += 1;
            continue;
        };
        if decoded.subject != ClaimSubject::Entity(claim) {
            continue;
        }
        about_claim.push(format!("{} ({:?})", decoded.predicate, decoded.approval));
        if !wanted.contains(&decoded.predicate.as_str()) {
            continue;
        }
        let Some(text) = decoded.value.as_str() else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            continue;
        };
        if value.get("recheck").is_none() {
            continue;
        }
        if let Some(target) = value.get("target").and_then(serde_json::Value::as_str)
            && target != claim.to_hex()
        {
            continue;
        }
        return Ok(value);
    }
    Err(invalid(&format!(
        "no re-check finding for the claim: {unreadable} unreadable and {undecodable} \
         undecodable claim rows; claims about it: {about_claim:?}"
    )))
}
