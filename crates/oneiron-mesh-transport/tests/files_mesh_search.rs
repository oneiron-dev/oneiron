#![cfg(all(feature = "iroh", oneiron_test_support))]
//! Cross-device Files search over the mesh (census L2-16 PR 3; ARCH-0027
//! #files-world: "Cross-device search over the iroh mesh (OF-535). Each
//! device ranks its own files and returns metadata and snippets. One
//! calibrated merge orders the results across devices.").
//!
//! Two devices of the owner: two rooted carrier installs (test_doors::steward),
//! each with its own Files world (read on that install only, as shipped) and
//! its own landed files. Each vault holds the other's MACHINE, paired and bound
//! to its transport key as a host's enrolment leaves it, and the owner's grant
//! of `oneiron/files-search/1` to it. Each device serves its Files search on a
//! loopback iroh endpoint. Device A searches as the served door does: its own
//! answer, the other devices' answers over the mesh, one merge.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-mesh-transport --all-features --features oneiron/test-support
//! --test files_mesh_search`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, MachineOwnership, MachineRole, pairing_binding_transcript};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::note::{FileFacts, FolderRescan, ImportedNote, NameMatch};
use oneiron::registry::ENTITY_TYPE_MACHINE;
use oneiron::task_verb::sdk::{
    FilesMeaningState, FilesSearchDevices, FilesSearchMatch, FilesSourceSearchAnswer,
    FilesSourceSearchRequest, FilesUnreachedWhy, files_search_devices, merge_files_search_answers,
    search_files_sources_as,
};
use oneiron::test_doors::steward;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, TimeRange, Vault};
use oneiron_mesh_transport::files_search::{
    FILES_SEARCH_ALPN, FILES_SEARCH_DEADLINE, FilesSearchService, ask_files_search_devices,
};
use oneiron_mesh_transport::iroh_transport::IrohTransport;
use oneiron_mesh_transport::transport_key::TransportKey;
use oneiron_mesh_transport::{
    AcceptPolicy, MeshError, MeshMachineAddress, MeshService, MeshTransport, PairedMachineGrants,
    VaultMachineRoster, VaultPathReceipts,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// A file a device's folder holds as text: its path, its Markdown and when
/// it was last written.
type TextFile<'a> = (&'a str, &'a str, u64);

/// One device of the owner: its install, its Files source and its mesh
/// endpoint, which serves its Files search.
struct Device {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    /// This install's MACHINE.
    machine: EntityId,
    /// The device key its peers pair, from which its transport key derives.
    device: SigningKey,
    endpoint_key: [u8; 32],
    address: SocketAddr,
    mesh: Arc<IrohTransport>,
}

/// A device whose install is the owner's own machine, with one Files source
/// whose folder holds `files` as text, serving its Files search on a
/// loopback endpoint under `device_seed`'s transport key.
async fn device(device_seed: u8, files: &[TextFile<'_>]) -> TestResult<Device> {
    let dir = tempfile::tempdir()?;
    let vault =
        steward::open_owner_carrier_vault(dir.path()).map_err(at("open the carrier vault"))?;
    let owner = steward::owner(&vault).map_err(at("owner proof"))?;
    let machine = vault
        .local_machine()
        .map_err(at("read this install"))?
        .ok_or("fixture: this install has no machine id")?
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .map_err(at("the owner answers this install is his"))?;
    let (_world, source) = vault
        .attach_files_source(
            &owner,
            ActSurface::ThisInstall,
            "/srv/files",
            Vec::new(),
            None,
            None,
        )
        .map_err(at("attach the Files source"))?;
    land(&vault, &owner, &source.folder, &source.kind, files)?;

    let vault = Arc::new(vault);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let transport = TransportKey::derive(&device);
    let endpoint_key = transport.endpoint_key();
    let mesh = Arc::new(
        IrohTransport::bind_paired(
            transport,
            AcceptPolicy {
                roster: Arc::new(VaultMachineRoster(Arc::clone(&vault))),
                grants: Arc::new(PairedMachineGrants(Arc::clone(&vault))),
            },
            vec![FILES_SEARCH_ALPN.to_vec()],
            "127.0.0.1:0".parse()?,
            None,
            Arc::new(VaultPathReceipts(Arc::clone(&vault))),
        )
        .await
        .map_err(at("bind the mesh endpoint"))?,
    );
    let address = mesh
        .addr()
        .addrs
        .into_iter()
        .find_map(|addr| match addr {
            iroh::TransportAddr::Ip(ip) => Some(ip),
            _ => None,
        })
        .ok_or("fixture: the endpoint has no direct address")?;
    serve(Arc::clone(&mesh), Arc::clone(&vault));
    Ok(Device {
        _dir: dir,
        vault,
        owner,
        machine,
        device,
        endpoint_key,
        address,
        mesh,
    })
}

/// One whole rescan of the folder, as a host's walk hands it over: every
/// file lands as a note, and the notes' text is published for search.
fn land(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    folder: &str,
    kind: &str,
    files: &[TextFile<'_>],
) -> TestResult {
    let report = vault
        .rescan_folder_source(
            owner,
            FolderRescan {
                folder: folder.to_owned(),
                new: files
                    .iter()
                    .map(|(path, markdown, written_at)| ImportedNote {
                        path: (*path).to_owned(),
                        kind: kind.to_owned(),
                        title: Some((*path).to_owned()),
                        written_at: *written_at,
                        markdown: (*markdown).to_owned(),
                        original: None,
                    })
                    .collect(),
                links: Vec::new(),
                present: Vec::new(),
                name_only: Vec::new(),
                missing: Vec::new(),
                raw_hashes: HashMap::new(),
                facts: files
                    .iter()
                    .map(|(path, markdown, written_at)| {
                        (
                            (*path).to_owned(),
                            FileFacts {
                                bytes: u64::try_from(markdown.len()).unwrap_or(u64::MAX),
                                modified_at: *written_at,
                            },
                        )
                    })
                    .collect(),
                whole: true,
            },
        )
        .map_err(at("rescan the Files source"))?;
    assert_eq!(report.failed, 0, "no file may be refused: {report:?}");
    assert_eq!(report.landed, files.len(), "every file lands: {report:?}");
    vault
        .set_indexed_idle_delay_ms(0)
        .map_err(at("idle delay"))?;
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .map_err(at("publish the staged text"))?;
    assert!(
        published.failed.is_empty(),
        "every staged text publishes: {published:?}"
    );
    Ok(())
}

/// Serves `vault`'s Files search on `mesh`, each admitted connection in its
/// own task, as the server's accept loop does.
fn serve(mesh: Arc<IrohTransport>, vault: Arc<Vault>) {
    tokio::spawn(async move {
        let service = Arc::new(FilesSearchService::new(vault));
        loop {
            match mesh.accept().await {
                Ok(connection) => {
                    let service = Arc::clone(&service);
                    tokio::spawn(async move {
                        let _ = service.serve(connection).await;
                    });
                }
                Err(MeshError::Refused) => {}
                Err(_) => break,
            }
        }
    });
}

impl Device {
    /// This vault takes `peer` as one of the owner's machines: its MACHINE
    /// row, a pairing the peer's device key redeems, and the mesh binding of
    /// its transport key at its loopback address, as enrolment leaves them.
    /// The owner grants it Files search when `grant`.
    fn enrol(&self, peer: &Device, grant: bool) -> TestResult {
        let host = test_host_issuer();
        self.vault
            .put_entity(
                &peer.machine,
                ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                1,
                b"the owner's other device",
            )
            .map_err(at("the peer's MACHINE row"))?;
        let link = self
            .vault
            .issue_pairing_link(&host, Scope::top(), 3600)
            .map_err(at("issue a pairing link"))?;
        let device_key = peer.device.verifying_key().to_bytes();
        let transcript =
            pairing_binding_transcript(&link.code, &device_key, &peer.machine.to_hex())
                .map_err(at("pairing transcript"))?;
        let proof = peer.device.sign(&transcript).to_bytes();
        let pair = self
            .vault
            .redeem_pairing_link(
                &host,
                &link.code,
                &peer.machine.to_hex(),
                device_key,
                &proof,
            )
            .map_err(at("redeem the pairing link"))?;
        let (device_proof, transport_proof) =
            TransportKey::derive(&peer.device).binding_proofs(&peer.device, peer.machine);
        self.vault
            .bind_mesh_machine(
                &host,
                peer.machine,
                MeshMachineAddress {
                    endpoint_key: peer.endpoint_key,
                    direct_addrs: vec![peer.address],
                    relay_url: None,
                },
                device_key,
                pair.claims.slip_id,
                [&device_proof, &transport_proof],
            )
            .map_err(at("bind the peer's transport key"))?;
        if grant {
            self.grant(peer, true)?;
        }
        Ok(())
    }

    /// The owner grants (`allow`) or revokes Files search for `peer`.
    fn grant(&self, peer: &Device, allow: bool) -> TestResult {
        self.vault
            .set_mesh_alpn_grant(
                &test_host_issuer(),
                peer.machine,
                peer.endpoint_key,
                FILES_SEARCH_ALPN,
                allow,
            )
            .map_err(at("the owner's Files search grant"))?;
        Ok(())
    }

    /// A search of `query` across `devices`, as the served door runs it:
    /// this device's own answer, the other devices' answers asked over the
    /// mesh within `deadline`, and one merge.
    async fn search(
        &self,
        query: &str,
        devices: FilesSearchDevices,
        deadline: Duration,
    ) -> TestResult<FilesSourceSearchAnswer> {
        let request = FilesSourceSearchRequest {
            query: query.to_owned(),
            sources: None,
            limit: None,
            devices: Some(devices.clone()),
        };
        let machines =
            files_search_devices(&self.vault, &devices).map_err(at("the devices to ask"))?;
        let this = search_files_sources_as(&self.vault, &self.owner, request.clone())
            .map_err(at("this device's search"))?;
        let transport: Arc<dyn MeshTransport> = Arc::clone(&self.mesh) as Arc<dyn MeshTransport>;
        let (answered, unreached) =
            ask_files_search_devices(transport, machines, &request, deadline).await;
        Ok(merge_files_search_answers(
            request.limit,
            this,
            answered,
            unreached,
        ))
    }
}

/// Device A holds `budget.md` and a note about the trip's budget; device B
/// holds `budget-q4.md` and the quarter's plan, which names the budget.
async fn two_devices() -> TestResult<(Device, Device)> {
    let a = device(
        0x51,
        &[
            ("budget.md", "Spending lines for travel.\n", 1_780_000_200),
            (
                "notes/trip.md",
                "# Trip\n\nWe kept the budget for the trip.\n",
                1_780_000_000,
            ),
        ],
    )
    .await?;
    let b = device(
        0x52,
        &[
            (
                "budget-q4.md",
                "Lines for the fourth quarter.\n",
                1_780_000_300,
            ),
            (
                "notes/plan.md",
                "# Plan\n\nWe set the budget for the quarter.\n",
                1_780_000_100,
            ),
        ],
    )
    .await?;
    a.enrol(&b, true)?;
    b.enrol(&a, true)?;
    Ok((a, b))
}

fn listed(answer: &FilesSourceSearchAnswer) -> Vec<(&str, EntityId)> {
    answer
        .hits
        .iter()
        .map(|hit| (hit.handle.path.as_str(), hit.machine))
        .collect()
}

#[tokio::test]
async fn mesh_search_puts_every_name_hit_before_any_meaning_hit() -> TestResult {
    let (a, b) = two_devices().await?;

    let answer = a
        .search("budget", FilesSearchDevices::All, FILES_SEARCH_DEADLINE)
        .await?;

    assert!(
        answer.unreached.is_empty(),
        "both devices answer: {answer:?}"
    );
    assert_eq!(answer.meaning, FilesMeaningState::Ran, "{answer:?}");
    assert_eq!(
        listed(&answer),
        vec![
            ("budget.md", a.machine),
            ("budget-q4.md", b.machine),
            ("notes/trip.md", a.machine),
            ("notes/plan.md", b.machine),
        ],
        "every name hit of both devices, by class, then the meaning hits by each device's rank, \
         this device first on a tie: {answer:?}"
    );
    let matched: Vec<FilesSearchMatch> = answer.hits.iter().map(|hit| hit.matched).collect();
    assert_eq!(
        matched,
        vec![
            FilesSearchMatch::Name {
                class: NameMatch::Exact
            },
            FilesSearchMatch::Name {
                class: NameMatch::Prefix
            },
            FilesSearchMatch::Meaning { rank: 1 },
            FilesSearchMatch::Meaning { rank: 1 },
        ],
        "{answer:?}"
    );
    // L2-16-MESH-SNIPPETS = B: B's Files world is read on B only, and B
    // still sends its snippet to A, a machine holding the grant.
    let plan = &answer.hits[3];
    assert!(
        plan.snippet
            .as_deref()
            .is_some_and(|snippet| snippet.contains("budget")),
        "B's meaning hit carries its snippet: {plan:?}"
    );
    assert!(
        plan.revision.is_some() && plan.modified_at == Some(1_780_000_100),
        "B's hit carries its file's metadata: {plan:?}"
    );
    Ok(())
}

#[tokio::test]
async fn mesh_search_lists_a_machine_without_the_grant_as_unreached() -> TestResult {
    let (a, b) = two_devices().await?;
    a.grant(&b, false)?;

    let answer = a
        .search(
            "budget",
            FilesSearchDevices::Only(vec![b.machine]),
            FILES_SEARCH_DEADLINE,
        )
        .await?;

    assert_eq!(answer.unreached.len(), 1, "{answer:?}");
    assert_eq!(answer.unreached[0].machine, b.machine, "{answer:?}");
    assert_eq!(
        answer.unreached[0].why,
        FilesUnreachedWhy::Refused,
        "this vault no longer grants B Files search, so it is never dialed: {answer:?}"
    );
    assert_eq!(
        listed(&answer),
        vec![("budget.md", a.machine), ("notes/trip.md", a.machine)],
        "this device's own hits still answer: {answer:?}"
    );
    // A machine without the grant is not one of "all" either.
    let all = a
        .search("budget", FilesSearchDevices::All, FILES_SEARCH_DEADLINE)
        .await?;
    assert!(all.unreached.is_empty(), "{all:?}");
    assert!(
        all.hits.iter().all(|hit| hit.machine == a.machine),
        "{all:?}"
    );
    Ok(())
}

#[tokio::test]
async fn mesh_search_gets_nothing_from_a_device_that_no_longer_grants_the_asker() -> TestResult {
    let (a, b) = two_devices().await?;
    b.grant(&a, false)?;

    let answer = a
        .search(
            "budget",
            FilesSearchDevices::Only(vec![b.machine]),
            FILES_SEARCH_DEADLINE,
        )
        .await?;

    assert_eq!(
        answer
            .unreached
            .iter()
            .map(|device| device.machine)
            .collect::<Vec<_>>(),
        vec![b.machine],
        "B refuses A, so B is listed unreached: {answer:?}"
    );
    assert!(
        answer.hits.iter().all(|hit| hit.machine == a.machine),
        "no hit, metadata or snippet of B's reaches A: {answer:?}"
    );
    Ok(())
}

#[tokio::test]
async fn mesh_search_lists_a_silent_device_as_unreached_within_the_deadline() -> TestResult {
    let (a, b) = two_devices().await?;
    b.mesh.shutdown().await.map_err(at("stop B's endpoint"))?;
    let deadline = Duration::from_secs(3);

    let started = Instant::now();
    let answer = a
        .search("budget", FilesSearchDevices::All, deadline)
        .await?;

    assert!(
        started.elapsed() < deadline + Duration::from_secs(5),
        "the search waits for a silent device no longer than its deadline: {:?}",
        started.elapsed()
    );
    assert_eq!(
        answer
            .unreached
            .iter()
            .map(|device| device.machine)
            .collect::<Vec<_>>(),
        vec![b.machine],
        "{answer:?}"
    );
    assert_eq!(
        listed(&answer),
        vec![("budget.md", a.machine), ("notes/trip.md", a.machine)],
        "this device's own hits still answer: {answer:?}"
    );
    Ok(())
}
