//! L4-20 PR 2 (ARCH-0077 slides lane, `slides:oracle`): a deck created through the engine's public doors carries the
//! fit PowerPoint measured for those exact bytes in a stored Office receipt, and nothing more.
//!
//! The deck is the `deck-create-v1` case `wide-table` (its stored receipt: the title fits, the table is inconclusive
//! because PowerPoint for Mac's AppleScript dictionary gives no table rows). It is the one case with no claim, so its
//! outline cites no evidence the vault would have to hold. A one-word change gives a deck no receipt names, which
//! keeps every unit unverified: "Estimates choose candidates; they do not certify fit."
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test deck_fit_certified`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::blob_artifact::deck_creation::outline::DeckOutline;
use oneiron::blob_artifact::deck_creation::record::{ArtifactVersionRef, DeckCreationRecord};
use oneiron::blob_artifact::deck_creation::{
    DeckDesignRequest, DeckEmissionNames, DeckEmissionOutcome, DeckEmissionRequest,
    DeckKeepBinding, DeckOutlineProposeRequest, DeckOutlineSettleRequest,
};
use oneiron::memory::{BlobArtifactInput, BlobVersionAppendOutcome, Memory};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_docedit::emit::oracle_cases;
use sha2::Digest as _;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CASE: &str = "wide-table";
const PPTX: &str = "application/vnd.openxmlformats-officedocument.presentationml.presentation";

/// The repository root above this crate.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn brief_bytes() -> TestResult<Vec<u8>> {
    let loaded = oracle_cases::load(&repo())?;
    let case = loaded
        .set
        .cases
        .iter()
        .find(|case| case.id == CASE)
        .ok_or("no wide-table case")?;
    Ok(std::fs::read(repo().join(&case.brief))?)
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"deck fit certified integration host")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        Ok(Self {
            vault,
            owner,
            _dir: dir,
        })
    }

    fn owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The case set's template as a blob artifact version.
    fn template(&self) -> TestResult<ArtifactVersionRef> {
        let loaded = oracle_cases::load(&repo())?;
        let owner = self.owner();
        let now = self.vault.now_recorded_at();
        let artifact = EntityId::now();
        owner.put_blob_artifact(&BlobArtifactInput {
            id: Some(artifact.to_hex()),
            name: "deck-create-template.pptx".to_owned(),
            media_type: PPTX.to_owned(),
            occurred_at: Some(now),
            learned_at: None,
        })?;
        match owner.append_blob_version(
            &artifact.to_hex(),
            &loaded.template_bytes,
            None,
            now,
            None,
        )? {
            BlobVersionAppendOutcome::Landed(view) => Ok(ArtifactVersionRef {
                artifact,
                version: view.version,
            }),
            other => Err(format!("FIXTURE: the template version did not land: {other:?}").into()),
        }
    }

    /// Propose the outline, keep it, design it over `template` and create its deck.
    fn create(
        &self,
        outline: &[u8],
        template: ArtifactVersionRef,
    ) -> TestResult<DeckCreationRecord> {
        let owner = self.owner();
        owner.bless_brief_kind()?;
        let outline: DeckOutline = serde_json::from_slice(outline)?;
        let view = owner.artifacts_propose_outline(&DeckOutlineProposeRequest { outline })?;
        let kept = owner.artifacts_keep_outline(&DeckOutlineSettleRequest {
            outline_ref: view.outline_ref.clone(),
            expected_frontier: view.frontier.clone(),
        })?;
        let binding = || DeckKeepBinding {
            version: kept.version.clone(),
            content_hash: kept.content_hash,
        };
        let design = owner.artifacts_design_deck(&DeckDesignRequest {
            outline_ref: view.outline_ref.clone(),
            kept: binding(),
            templates: vec![template],
            assets: Default::default(),
            fonts: Vec::new(),
            why: None,
        })?;
        assert!(
            matches!(design.plans.as_slice(), [Some(_)]),
            "FIXTURE: the template is a planned direction: {:?}",
            design.decisions
        );
        let loaded = oracle_cases::load(&repo())?;
        let names = &loaded.set.names;
        let outcome = owner.artifacts_create_deck(&DeckEmissionRequest {
            outline_ref: view.outline_ref,
            kept: binding(),
            template,
            assets: Default::default(),
            fonts: Vec::new(),
            graphics: None,
            names: DeckEmissionNames {
                text: names.text.clone(),
                table: names.table.clone(),
                chart: names.chart.clone(),
                picture: names.picture.clone(),
                figure: names.figure.clone(),
                sheet: names.sheet.clone(),
            },
            name: "Site costs".to_owned(),
            run_ref: format!("deck-fit-certified-{}", EntityId::now().to_hex()),
            trigger: None,
        })?;
        match outcome {
            DeckEmissionOutcome::Created { record } => Ok(*record),
            DeckEmissionOutcome::Ask { pages } => {
                Err(format!("FIXTURE: creation asked about pages {pages:?}").into())
            }
        }
    }
}

/// The deck the engine creates from the case's outline is byte for byte the receipted candidate, so it carries the
/// receipt: the title PowerPoint measured as fitting is certified, the table it could not measure stays unverified.
#[test]
fn a_deck_born_from_a_receipted_case_carries_its_receipt() -> TestResult {
    let fixture = Fixture::open()?;
    let template = fixture.template()?;
    let record = fixture.create(&brief_bytes()?, template)?;

    let root = repo();
    let loaded = oracle_cases::load(&root)?;
    let case = loaded
        .set
        .cases
        .iter()
        .find(|case| case.id == CASE)
        .ok_or("no wide-table case")?;
    let receipted = oracle_cases::case_candidate(&root, &loaded, case)?;
    assert_eq!(
        record.content_hash, receipted.candidate.hash,
        "the engine writes the deck the case runner wrote"
    );
    let receipt = std::fs::read(
        root.join(oracle_cases::STORED_RESULTS)
            .join(CASE)
            .join("receipt.json"),
    )?;
    // The receipt was made by the case runner built alone; this build links the engine, whose dependency graph
    // switches flate2 to another backend. The package bytes must not follow it.
    let opened: serde_json::Value = serde_json::from_slice(&receipt)?;
    assert_eq!(
        opened
            .pointer("/input/sha256")
            .and_then(serde_json::Value::as_str),
        Some(oracle_cases::sha256_hex(&receipted.candidate.bytes).as_str()),
        "the engine's build writes the bytes PowerPoint opened"
    );
    let receipt_sha256: [u8; 32] = sha2::Sha256::digest(&receipt).into();
    assert_eq!(record.fit_receipt, Some(receipt_sha256));

    let slide = record.slides.first().ok_or("no slide")?.part.clone();
    let blocks: Vec<&str> = record
        .fit_unverified
        .iter()
        .map(|(_, block, _)| block.as_str())
        .collect();
    assert_eq!(blocks, ["s-table"], "only the table stays unverified");
    assert!(
        record
            .fit_unverified
            .iter()
            .all(|(part, _, _)| *part == slide)
    );
    assert!(record.fit_overflows.is_empty());
    Ok(())
}

/// One changed word: no stored receipt names the deck, so every unit stays unverified and no receipt is named.
#[test]
fn a_deck_with_no_receipt_stays_fit_unverified() -> TestResult {
    let fixture = Fixture::open()?;
    let template = fixture.template()?;
    let held = String::from_utf8(brief_bytes()?)?;
    let changed = held.replacen("Site costs by region", "Site costs by area", 1);
    assert_ne!(changed, held, "the wide-table brief titles its page");
    let record = fixture.create(changed.as_bytes(), template)?;

    let mut blocks: Vec<&str> = record
        .fit_unverified
        .iter()
        .map(|(_, block, _)| block.as_str())
        .collect();
    blocks.sort_unstable();
    assert_eq!(blocks, ["s-table", "s-title"]);
    assert!(record.fit_overflows.is_empty());
    assert_eq!(record.fit_receipt, None);
    Ok(())
}

/// A record stored before receipts were read has no `fit_overflows` and no `fit_receipt` key. It still reads under the
/// store's encoding (`rmp_serde::to_vec_named`, a map per record), with no overflow and no receipt.
#[test]
fn a_record_stored_before_receipts_still_reads() -> TestResult {
    let fixture = Fixture::open()?;
    let template = fixture.template()?;
    let record = fixture.create(&brief_bytes()?, template)?;

    let bytes = rmp_serde::to_vec_named(&record)?;
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut bytes.as_slice())? else {
        return Err("a named record is a map".into());
    };
    let count = entries.len();
    let older: Vec<(rmpv::Value, rmpv::Value)> = entries
        .into_iter()
        .filter(|(key, _)| !matches!(key.as_str(), Some("fit_overflows" | "fit_receipt")))
        .collect();
    assert_eq!(older.len() + 2, count, "the record names both fields");
    let mut written = Vec::new();
    rmpv::encode::write_value(&mut written, &rmpv::Value::Map(older))?;

    let read: DeckCreationRecord = rmp_serde::from_slice(&written)?;
    assert!(read.fit_overflows.is_empty());
    assert_eq!(read.fit_receipt, None);
    assert_eq!(read.fit_unverified, record.fit_unverified);
    assert_eq!(read.content_hash, record.content_hash);
    Ok(())
}
