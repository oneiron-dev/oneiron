//! K-proof (oracle) for [CAL-ICS-CONSENT-RAW-HASHER]: an installed ICS feed's consent digests
//! keep their bytes.
//!
//! The feed's configuration digest (`purposes::calendar::ICS_FEED_CONFIG_DIGEST`) and its
//! first-poll review ref (`purposes::calendar::ICS_FEED_REVIEW_REF`) now start through the
//! fingerprint crate's K door. Each consent record stores the configuration digest and every
//! read compares it, so a changed recipe would drop each feed's standing consent. The review
//! ref is sent in the feed's status and compared at the owner's decision. So both must give
//! main's bytes. The two functions after the imports are main's lines at ef184a16ff72
//! (crates/oneiron/src/calendar/ingest/consent.rs:88-101), copied unchanged; `crate::Result`
//! and `crate::Error` name the library's own, as there.
//!
//! The review ref is built from the stored configuration digest, so a status ref equal to
//! main's recipe over the feed's configuration proves both digests. A review holds the poll's
//! admitted claims in admission order; the store clock mints each claim id above the last
//! one, so that order is the ids' order.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test fingerprint_keep_calendar_ics_consent`.
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};

use oneiron::calendar::CalendarError;
use oneiron::calendar::claims::PREDICATE_CALENDAR_ORIGIN;
use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConfigureRequest, CalendarIcsFeedConsent, CalendarIcsFeedRequest,
    CalendarIcsFeedReviewDecision, CalendarIcsFeedReviewRequest,
};
use oneiron::calendar::ingest::{IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse};
use oneiron::calendar::passport::resolve_event_by_uid;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Error, Result, Vault, VaultConfig};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_keystore::MemoryKeystore;

fn config_digest(config: &IcsFeedPollConfig) -> crate::Result<String> {
    let bytes = serde_json::to_vec(config)
        .map_err(|_| crate::Error::InvariantViolation("ICS feed config did not encode"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// The ref of one exact review: the feed's configuration and its claim set.
fn review_ref(config_digest: &str, claim_ids: &[String]) -> crate::Result<String> {
    let bytes = serde_json::to_vec(&(config_digest, claim_ids))
        .map_err(|_| crate::Error::InvariantViolation("ICS feed review did not encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron calendar.ics.review v1");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
}

impl Fixture {
    /// A seeded vault (the shipped policy manifest holds each imported
    /// claim), rooted, its engine machines enrolled, and its owner.
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config).expect("seeded vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        oneiron::test_support::provision_engine_machines(&vault);
        let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            _dir: dir,
            vault,
            owner,
            proof,
        }
    }

    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn install(&self, config: &IcsFeedPollConfig) {
        feed::configure(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedConfigureRequest {
                config: config.clone(),
            },
        )
        .expect("install the feed");
    }

    fn poll(&self, config: &IcsFeedPollConfig, response: IcsFetchResponse) {
        feed::run_installed_poll(
            &self.memory(),
            &self.proof,
            &StubFetcher::with([response]),
            None,
            config,
            EntityId::now().to_hex(),
        )
        .expect("first poll");
    }

    fn consent(&self, system: &str) -> CalendarIcsFeedConsent {
        feed::status(
            &self.memory(),
            &self.proof,
            &CalendarIcsFeedRequest {
                system: system.to_owned(),
            },
        )
        .expect("feed status")
        .expect("installed feed")
        .consent
    }

    /// The claims the feed imported about the EVENTs `uids` name (every claim
    /// but the projector-written `calendar.origin`), as ids in the order the
    /// store clock minted them.
    fn imported_claim_ids(&self, uids: &[&str]) -> Vec<String> {
        let mut ids = Vec::new();
        for uid in uids {
            let event = resolve_event_by_uid(&self.vault, uid)
                .expect("resolve uid")
                .expect("event for uid");
            for id in self
                .vault
                .claims_for_subject(&event)
                .expect("claims for subject")
            {
                let body = self
                    .vault
                    .get_claim(&id)
                    .expect("get claim")
                    .expect("claim");
                if body.predicate != PREDICATE_CALENDAR_ORIGIN {
                    ids.push(id);
                }
            }
        }
        ids.sort();
        ids.iter().map(EntityId::to_hex).collect()
    }
}

/// A scripted fetcher: replays queued responses.
struct StubFetcher {
    responses: Mutex<std::collections::VecDeque<IcsFetchResponse>>,
}

impl StubFetcher {
    fn with(responses: impl IntoIterator<Item = IcsFetchResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl IcsFeedFetcher for StubFetcher {
    fn fetch(
        &self,
        _secret_ref: &str,
        _if_none_match: Option<&str>,
    ) -> std::result::Result<IcsFetchResponse, CalendarError> {
        self.responses
            .lock()
            .expect("responses")
            .pop_front()
            .ok_or_else(|| CalendarError::IcsFetch {
                reason: "stub fetcher has no queued response".to_owned(),
            })
    }
}

/// A complete VCALENDAR body holding one VEVENT per UID.
fn complete(uids: &[&str], etag: &str) -> IcsFetchResponse {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for uid in uids {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{uid}\r\n"));
        out.push_str("DTSTAMP:20260805T100000Z\r\n");
        out.push_str("DTSTART:20260806T140000Z\r\n");
        out.push_str("DTEND:20260806T150000Z\r\n");
        out.push_str("SEQUENCE:1\r\n");
        out.push_str("SUMMARY:standup\r\n");
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    IcsFetchResponse::Complete {
        etag: Some(etag.to_owned()),
        body: out.into_bytes(),
    }
}

fn open_review(consent: CalendarIcsFeedConsent) -> (u32, String) {
    match consent {
        CalendarIcsFeedConsent::AwaitingReview { claims, review_ref } => (claims, review_ref),
        other => panic!("expected an open review, got {other:?}"),
    }
}

#[test]
fn the_calendar_purposes_keep_main_s_recipes() {
    let config = purposes::calendar::ICS_FEED_CONFIG_DIGEST;
    assert_eq!(config.tag(), "oneiron.calendar.ics_feed_config_digest.v1");
    assert_eq!(config.hash(), LegacyHash::Blake3);
    assert_eq!(config.tag_mode(), TagMode::NotHashed);

    let review = purposes::calendar::ICS_FEED_REVIEW_REF;
    assert_eq!(review.tag(), "oneiron calendar.ics.review v1");
    assert_eq!(review.hash(), LegacyHash::Blake3);
    assert_eq!(review.tag_mode(), TagMode::DeriveKeyContext);
}

#[test]
fn each_feed_s_review_ref_is_main_s_recipe_and_the_owner_decides_on_it() {
    let f = Fixture::open();
    let feeds = [
        (
            IcsFeedPollConfig {
                secret_ref: "ics-feed:work".to_owned(),
                system: "work".to_owned(),
                cadence_min_seconds: 300,
                cadence_max_seconds: 900,
            },
            vec!["uid-1@work"],
        ),
        (
            IcsFeedPollConfig {
                secret_ref: "ics-feed:home \"family\" 家族".to_owned(),
                system: "home".to_owned(),
                cadence_min_seconds: 60,
                cadence_max_seconds: 86_400,
            },
            vec!["uid-1@home", "uid-2@home", "uid-3@home"],
        ),
    ];
    for (config, uids) in &feeds {
        f.install(config);
        f.poll(config, complete(uids, "v1"));

        let ids = f.imported_claim_ids(uids);
        let (claims, status_ref) = open_review(f.consent(&config.system));
        assert_eq!(
            claims as usize,
            ids.len(),
            "{}: the review holds every claim the first poll imported",
            config.system
        );
        let main_ref = review_ref(
            &config_digest(config).expect("main's configuration digest"),
            &ids,
        )
        .expect("main's review ref");
        assert_eq!(main_ref.len(), 64);
        assert_eq!(
            status_ref, main_ref,
            "{}: the status sends main's review ref over the stored configuration digest",
            config.system
        );

        let decided = feed::review(
            &f.memory(),
            &f.proof,
            &CalendarIcsFeedReviewRequest {
                system: config.system.clone(),
                review_ref: main_ref,
                decision: CalendarIcsFeedReviewDecision::Approve,
            },
        )
        .expect("the owner decides on main's review ref");
        assert!(
            matches!(decided, CalendarIcsFeedConsent::Granted { .. }),
            "{}: expected the standing consent, got {decided:?}",
            config.system
        );
        assert_eq!(
            f.consent(&config.system),
            decided,
            "{}: the stored consent reads back under the same configuration digest",
            config.system
        );
    }
}
