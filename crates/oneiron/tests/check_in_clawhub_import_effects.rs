//! ROLES-CHECKIN P2.5, row 2k8d2 (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine rulings P25-SHAPE Q1 = A, 14 Nov
//! 13:39, and P25-2K8-SCOPE Q1 = A, 19:32): the Owner-proof door
//! `vault.skill_hubs.clawhub.import` takes the 2j apply shape.
//!
//! - The Owner's import is never gated: it goes on their own proof, and the
//!   answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   import: the import's commit writer spends it, and the answer names it
//!   and its asker. An approval for another import changes nothing and
//!   stays unspent.
//! - An import that applies a check-in carries `expected_content_hash`, so
//!   the ask names the exact bytes (ruling P25-2K8-SCOPE Q1). Without it the
//!   import is refused before any fetch, and the check-in stays unspent.
//! - The import admits its publisher in a writer of its own, before the
//!   import's: a check-in for another import is refused before any fetch,
//!   so it admits no one (2k8d review).
//!
//! On its base, 2k8d's head, this file does not build: the ClawHub request
//! has no `check_in_ref`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_clawhub_import_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/hub_fixture.rs"]
mod hub_fixture;
#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hub_fixture::{configured_hub, publisher_grant_ref, skill_md};
use oneiron::EntityId;
use oneiron::check_in::ActClass;
use oneiron::skill::canonical_skill_tree_hash;
use oneiron::skill_hub::{
    ClawHubImportReply, ClawHubImportRequest, HubPin, HubSyncPolicy, SkillHubKind,
};
use oneiron::verbs::{clawhub_import_effect_digest, skill_hub_clawhub_import_as_owner};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

/// The native content hash of a skill whose one file is `skill_md`.
fn tree_hash(skill_md: &[u8]) -> String {
    canonical_skill_tree_hash([("SKILL.md", skill_md)])
        .expect("the tree hashes")
        .to_hex()
}

/// A loopback HTTP server answering each GET path from `routes`, else 404.
struct StaticHttp {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl StaticHttp {
    fn new(routes: BTreeMap<String, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture's address");
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            for connection in listener.incoming() {
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let mut stream = connection.expect("a connection");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .expect("a read timeout");
                let mut reader = BufReader::new(stream.try_clone().expect("a reader"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("the request line");
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                loop {
                    line.clear();
                    reader.read_line(&mut line).expect("a header");
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                let (status, body) = routes
                    .get(&path)
                    .map_or((404, Vec::new()), |body| (200, body.clone()));
                write!(
                    stream,
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .expect("the response head");
                stream.write_all(&body).expect("the response body");
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }

    fn index_url(&self) -> String {
        format!("http://{}/index.json", self.address)
    }
}

impl Drop for StaticHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("the HTTP fixture");
        }
    }
}

/// A ClawHub download: a zip holding `skill_md` as its root SKILL.md.
fn zip_of(skill_md: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    archive
        .start_file(
            "SKILL.md",
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .expect("a zip entry");
    archive.write_all(skill_md).expect("the entry's bytes");
    archive.finish().expect("the zip").into_inner()
}

fn clawhub_request(
    hub: EntityId,
    slug: &str,
    publisher: &str,
    expected_content_hash: Option<String>,
    check_in_ref: Option<EntityId>,
) -> ClawHubImportRequest {
    ClawHubImportRequest {
        hub,
        slug: slug.to_owned(),
        version: None,
        tag: None,
        publisher: publisher.to_owned(),
        expected_skill_id: None,
        expected_skill_version: None,
        expected_content_hash,
        response_limit_bytes: None,
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_clawhub_import_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let (own_md, asked_md) = (skill_md("fixture.own"), skill_md("fixture.asked"));
    let server = StaticHttp::new(BTreeMap::from([
        ("/api/v1/download?slug=own".to_owned(), zip_of(&own_md)),
        ("/api/v1/download?slug=asked".to_owned(), zip_of(&asked_md)),
    ]));
    let hub = configured_hub(
        &vault,
        &owner_proof,
        SkillHubKind::HttpIndex,
        &server.index_url(),
        HubSyncPolicy::ContentHashFrozen,
    );

    let own = skill_hub_clawhub_import_as_owner(
        &vault,
        &owner_proof,
        &clawhub_request(hub, "own", "publisher:own", None, None),
    )
    .expect("the Owner imports from ClawHub");
    let (source, own_check_in) = match own {
        ClawHubImportReply::Imported {
            source, check_in, ..
        } => (source, check_in),
        other => panic!("the fixture serves the skill; seen {other:?}"),
    };
    assert_eq!(
        source.pin,
        HubPin::ContentHash(tree_hash(&own_md)),
        "the fixture's hash is the one the import pins"
    );
    assert_eq!(
        own_check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own import records their own proof"
    );

    let asked_hash = tree_hash(&asked_md);
    let asked = clawhub_request(
        hub,
        "asked",
        "publisher:asked",
        Some(asked_hash.clone()),
        None,
    );
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.skill_hubs.clawhub.import",
        ActClass::GrantWiden,
        &clawhub_import_effect_digest(&asked).expect("the import's digest"),
    );
    let unpinned = skill_hub_clawhub_import_as_owner(
        &vault,
        &owner_proof,
        &clawhub_request(hub, "asked", "publisher:asked", None, Some(check_in)),
    )
    .expect_err("an import without expected_content_hash names no exact bytes");
    assert!(
        format!("{unpinned:?}").contains("expected_content_hash"),
        "refused for its missing hash, before any fetch; seen {unpinned:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    let other = skill_hub_clawhub_import_as_owner(
        &vault,
        &owner_proof,
        &clawhub_request(
            hub,
            "asked",
            "publisher:other",
            Some(asked_hash.clone()),
            Some(check_in),
        ),
    );
    assert!(
        other.is_err(),
        "the approval covers the publisher it was asked for only; seen {other:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    assert!(
        vault
            .consent_grant(&publisher_grant_ref("publisher:other", hub))
            .expect("read the Grant")
            .is_none(),
        "the refused import admitted no publisher"
    );

    let imported = skill_hub_clawhub_import_as_owner(
        &vault,
        &owner_proof,
        &clawhub_request(
            hub,
            "asked",
            "publisher:asked",
            Some(asked_hash),
            Some(check_in),
        ),
    )
    .expect("the Owner applies the approved ask");
    let decision = match imported {
        ClawHubImportReply::Imported { check_in, .. } => check_in,
        other => panic!("the fixture serves the skill; seen {other:?}"),
    };
    assert!(spent(&vault, &check_in), "the import spent the check-in");
    assert_eq!(
        decision,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}
