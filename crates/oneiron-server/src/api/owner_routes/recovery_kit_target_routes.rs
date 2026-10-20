//! The target install's own kit calls (FIX 4736, 4530, 4564): the material
//! a root change or a late joiner's pad access needs, supplied by the owner
//! on whichever authenticated surface reaches this install, for this one
//! call alone. Never stored, logged or put in a receipt, and never relayed:
//! a coordinating install records the request ids-only
//! (`root_routes`), and only the target's own call carries a seed's kit,
//! a piece or a passphrase.
//!
//! - `POST /roots/requests/run`: runs a root request pending on this install
//!   with its material (`Vault::run_root_request`). An activation is two
//!   calls: `issue_kit` answers the new kit's pieces, as recovery codes, to
//!   this caller only, and `confirm_kit` reads two back (or one and the
//!   passphrase) and closes the request. A restore and an anchoring take the
//!   bound root's kit. The answer is the target's report and its words
//!   (`RootWorkDone::text`), to this caller alone.
//! - `POST /recovery-kit/pad-access`: the owner's kit grants a machine every
//!   pad object the home keeps (`SyncClient::grant_sealed_bundle_pad_access_with_kit`,
//!   through this install's own home connection): what was offered, what is
//!   usable here, and what stays pending with the home.
//!
//! A kit is always its pieces (recovery codes) and the passphrase where one
//! point is the passphrase: the engine rebuilds the seed and checks it, and
//! no bare seed bytes are taken.
//!
//! The recipient rule (Engine 10-19 09:3x, CALLS "owneract kit transport"):
//! each call names its `target`, and kit material goes only in the body of
//! that target's own call. The target must be this install, proved by its
//! machine proof, and a machine the worlds' privacy lets hold their keys, as
//! the verified-destination judge reads it: one of the owner's own machines
//! (marked mine) for one-machine and my-machines worlds, and any proven
//! machine where no world keeps its keys off it. An unproved or disallowed
//! target gets a named refusal before any kit is parsed ([`kit_target`]).
//!
//! The console never receives the recovery seed (DEC-0005, FIX 6028): while
//! [`OWNER_DEVICE_ONLY_KIT_TARGETS`] holds, a hosted or managed install takes
//! no kit material at all. Both calls refuse there with
//! `kit_requires_owner_device` before their body is read ([`OwnerDevice`]);
//! the owner still says so from any surface and the work runs on his own
//! device.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::{Destination, OwnerWorkRefusal, PeerMachine, RequestCode};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    KitCoverage, KitIssue, KitPassphrase, KitPiece, KitSecretKind, PassphraseCost, PieceHome,
    restore_kit,
};
use oneiron::settings::{ReadDestination, RecipientLimit, RecipientWhy};
use oneiron::sync::residence::sealed_generation_hex;
use oneiron::world_keys::{
    PadAdmissionTarget, RecoveryRootSeed, RepinReport, RootMaterial, RootRestore, RootSecret,
    RootWorkDone, SealedBundleGeneration, Withheld, WorldKeyId,
};
use oneiron::{EntityId, HostingPrivacyPosture, Vault};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::owner_work_routes::request_entry;
use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::api::pairing::MachineEnrolment;
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use crate::owner::recovery_kit::kit_id;
use crate::owner::vault_key::{WrapView, hex};
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/roots/requests/run", post(run))
        .route("/recovery-kit/pad-access", post(pad_access))
}

/// The material for one pending root request, as the target's caller
/// supplies it. No `Debug`: it carries the kit.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum Material {
    /// An activation's first step: a kit for a fresh root, over the homes
    /// the owner picked, with the passphrase when a home is one.
    IssueKit {
        homes: [PieceHome; 3],
        #[serde(default)]
        passphrase: Option<String>,
    },
    /// An activation's second step: the kit's pieces as saved, and the
    /// machines (32 hex) the new root carries.
    ConfirmKit {
        pieces: Vec<String>,
        #[serde(default)]
        passphrase: Option<String>,
        #[serde(default)]
        carry: Vec<String>,
    },
    /// A restore: the bound root's kit.
    Restore {
        pieces: Vec<String>,
        #[serde(default)]
        passphrase: Option<String>,
    },
    /// An anchoring: the bound root's kit, the machine's enrolment request
    /// (as `POST /v1/pairing/redeem` takes it), and the code that machine
    /// shows when it is not this one, 32 hex.
    Anchor {
        pieces: Vec<String>,
        #[serde(default)]
        passphrase: Option<String>,
        enrolment: Box<MachineEnrolment>,
        #[serde(default)]
        code: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRootRequest {
    /// The install this call's material is for, 32 hex: this one.
    target: String,
    /// The pending request, 64 hex: its receipt's `request`.
    request: String,
    material: Material,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PadAccess {
    /// The install this call's kit is for, 32 hex: this one.
    target: String,
    /// The kit's pieces, as recovery codes.
    pieces: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
    /// The machine to grant, 32 hex; none grants this install.
    #[serde(default)]
    machine: Option<String>,
}

/// The named refusals of the recipient rule ([`kit_target`]).
const KIT_TARGET_ELSEWHERE: &str = "kit_target_elsewhere";
const KIT_TARGET_UNPROVED: &str = "kit_target_unproved";
const KIT_TARGET_NOT_ALLOWED: &str = "kit_target_not_allowed";
const KIT_REQUIRES_OWNER_DEVICE: &str = "kit_requires_owner_device";

/// Canon (DEC-0005, FIX 6028): the console never receives the recovery seed.
/// While this holds, a hosted or managed install is no kit target: both
/// target calls refuse there before their body is read, and the target judge
/// no longer admits the host of a hosted vault. False keeps the hosted
/// target the recipient rule admitted before.
const OWNER_DEVICE_ONLY_KIT_TARGETS: bool = true;

/// Whether this install is hosted or managed, as it knows itself: a managed
/// issuer, or the hosted posture it was opened under. Never read from the
/// request.
fn hosted_install(server: &SyncServer) -> bool {
    server.managed_issuer.is_some()
        || server.vault().privacy_posture() == HostingPrivacyPosture::Hosted
}

/// The guard both target calls extract before their body (FIX 6028): on a
/// hosted or managed install, under [`OWNER_DEVICE_ONLY_KIT_TARGETS`], the
/// call is refused as `kit_requires_owner_device` and no kit is parsed.
struct OwnerDevice;

impl FromRequestParts<Arc<SyncServer>> for OwnerDevice {
    type Rejection = EnvelopedApiError;

    async fn from_request_parts(
        _: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        if OWNER_DEVICE_ONLY_KIT_TARGETS && hosted_install(server) {
            return Err(kit_target_refused(
                KIT_REQUIRES_OWNER_DEVICE,
                "this install is hosted: recovery kit work runs only on the owner's own device \
                 (your own machine or a self-hosted install), so it takes no kit here",
                "Run this from your own machine or self-hosted install; your say-so here still \
                 reaches it.",
            )
            .into());
        }
        Ok(Self)
    }
}

fn kit_target_refused(state: &str, message: &str, suggestion: &str) -> ApiError {
    ApiError::new(
        message,
        ApiErrorDetails::InvalidState {
            state: Some(state.to_owned()),
        },
        [suggestion],
    )
}

/// The recipient rule for kit material (CALLS "owneract kit transport"):
/// `named` must be this install, proved by the existing machine proof (this
/// install signs a connection proof and verifies it under the key it stands
/// on here, `PeerMachine::Proven`), and the worlds' privacy must let it hold
/// their keys. The verified-destination judge (`Vault::world_recipient_limit`,
/// mesh PR2b) reads each private world's recipient choice for that proved
/// machine: one of the owner's own machines may hold the keys of every
/// one-machine and my-machines world (a limit naming another of his machines,
/// or his contended picks, still admits his own), the host of a hosted vault
/// only while [`OWNER_DEVICE_ONLY_KIT_TARGETS`] is off, and any other machine
/// only where no world limits it. Each refusal is named and comes before any
/// kit is read.
fn kit_target(server: &SyncServer, named: &str) -> Result<EntityId, ApiError> {
    let named = EntityId::from_hex(named)
        .map_err(|_| ApiError::bad_request("target must be a 32-hex machine id", Some("target")))?;
    let vault = server.vault();
    let engine = |error: oneiron::Error| super::owner_error(error.into());
    let unproved = || {
        kit_target_refused(
            KIT_TARGET_UNPROVED,
            "this install's machine identity does not stand here under its own key, so it takes \
             no kit",
            "Enrol this install as one of the vault's machines, or wait for its profile to sync.",
        )
    };
    let token = format!("kit-target:{}", named.to_hex());
    let nonce = EntityId::now().to_hex();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let (machine, signature) = vault
        .machine_connection_proof(&token, timestamp, &nonce)
        .map_err(engine)?
        .ok_or_else(unproved)?;
    if machine != named {
        return Err(kit_target_refused(
            KIT_TARGET_ELSEWHERE,
            "the kit names another install as its target; this install takes no kit for it",
            "Send the kit to the named install's own call.",
        ));
    }
    let peer = vault
        .verify_machine_connection_proof(machine, &signature, &token, timestamp, &nonce)
        .map_err(engine)?;
    if !matches!(peer, PeerMachine::Proven { .. }) {
        return Err(unproved());
    }
    if !OWNER_DEVICE_ONLY_KIT_TARGETS && vault.privacy_posture() == HostingPrivacyPosture::Hosted {
        return Ok(named);
    }
    let destination = ReadDestination::toward(peer);
    let private = vault
        .authority_fold()
        .and_then(|fold| fold.worlds_withheld_from(Destination::Unknown))
        .map_err(engine)?;
    for world in private {
        let limit = vault
            .world_recipient_limit(world, &destination)
            .map_err(engine)?;
        match limit {
            None
            | Some(RecipientLimit {
                why: RecipientWhy::WrongMachine | RecipientWhy::Contended,
                ..
            }) => {}
            Some(limit) => {
                return Err(kit_target_refused(
                    KIT_TARGET_NOT_ALLOWED,
                    limit.reason(),
                    "Send the kit to one of your machines, or mark this machine yours first.",
                ));
            }
        }
    }
    Ok(named)
}

/// A kit as its caller gave it: the pieces, and the passphrase. Wiped on
/// drop.
struct Kit {
    pieces: Vec<KitPiece>,
    passphrase: Option<KitPassphrase>,
}

impl Kit {
    fn parse(pieces: Vec<String>, passphrase: Option<String>) -> OwnerResult<Self> {
        let codes = Zeroizing::new(pieces);
        let passphrase = Zeroizing::new(passphrase);
        let pieces = codes
            .iter()
            .enumerate()
            .map(|(at, code)| {
                KitPiece::from_recovery_code(code)
                    .map_err(|error| OwnerError::Invalid(format!("pieces[{at}]: {error}")))
            })
            .collect::<OwnerResult<Vec<_>>>()?;
        Ok(Self {
            pieces,
            passphrase: passphrase.as_deref().map(passphrase_of).transpose()?,
        })
    }

    fn pieces(&self) -> Vec<&KitPiece> {
        self.pieces.iter().collect()
    }

    /// The recovery root seed this kit rebuilds for `vault`, checked by the
    /// kit's own rules before anything is asked of the home.
    fn seed(&self, vault: &Vault) -> OwnerResult<RecoveryRootSeed> {
        let vault_id = vault_id(vault)?;
        let secret = restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &self.pieces(),
            self.passphrase.as_ref(),
        )
        .map_err(|error| OwnerError::Invalid(format!("the kit does not open: {error}")))?;
        Ok(RecoveryRootSeed::from_restored_kit(secret)?)
    }
}

fn passphrase_of(text: &str) -> OwnerResult<KitPassphrase> {
    KitPassphrase::new(text).map_err(|error| OwnerError::Invalid(format!("passphrase: {error}")))
}

/// The vault id kits are bound to.
fn vault_id(vault: &Vault) -> OwnerResult<[u8; 32]> {
    vault
        .world_kit_status()?
        .vault_id
        .ok_or_else(|| OwnerError::Refused("the vault has no authority genesis yet".to_owned()))
}

/// A machine's request code, as 32 lower-case hex (its 16 bytes).
fn request_code(text: &str) -> OwnerResult<RequestCode> {
    let refused = || OwnerError::Invalid("code must be 32 lower-case hex".to_owned());
    if text.len() != 32
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused());
    }
    let mut code = [0; 16];
    for (slot, pair) in code.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(RequestCode(code))
}

/// `POST /v1/owner/roots/requests/run`: runs the root request pending on
/// this install with the material its change needs. Missing or wrong
/// material is refused and the request stays pending; a stale request is
/// answered refused and closed.
async fn run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: Result<Json<RunRootRequest>, JsonRejection>,
) -> OwnerReply<RootWorkAnswer> {
    let owner = owner(&auth, &server)?;
    let body = json_payload(payload)?;
    kit_target(&server, &body.target)?;
    // The enrolment request reads as pairing reads it, before any work.
    let enrolment = match &body.material {
        Material::Anchor { enrolment, .. } => Some(enrolment.request()?),
        _ => None,
    };
    let answer = blocking(move || -> OwnerResult<RootWorkAnswer> {
        let request = request_entry("request", &body.request)?;
        let done = run_material(server.vault(), &owner, request, body.material, enrolment)?;
        Ok(RootWorkAnswer::of(server.vault(), done))
    })
    .await?;
    Ok(Json(answer))
}

fn run_material(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: [u8; 32],
    material: Material,
    enrolment: Option<oneiron::authority::MachineEnrolmentRequest>,
) -> OwnerResult<RootWorkDone> {
    let done = match material {
        Material::IssueKit { homes, passphrase } => {
            if homes.contains(&PieceHome::ThisMachine) {
                return Err(OwnerError::Invalid(
                    "a this_machine home waits for device-piece custody; pick another home"
                        .to_owned(),
                ));
            }
            let passphrase = Zeroizing::new(passphrase);
            let passphrase = passphrase.as_deref().map(passphrase_of).transpose()?;
            let issue = KitIssue {
                vault_id: vault_id(vault)?,
                homes,
                passphrase: passphrase.as_ref(),
                cost: PassphraseCost::DEFAULT,
                only_machine: false,
            };
            vault.run_root_request(owner, request, RootMaterial::IssueKit(&issue))?
        }
        Material::ConfirmKit {
            pieces,
            passphrase,
            carry,
        } => {
            let kit = Kit::parse(pieces, passphrase)?;
            let carry = carry
                .iter()
                .map(|machine| entity_id("carry", machine))
                .collect::<OwnerResult<BTreeSet<EntityId>>>()?;
            let pieces = kit.pieces();
            let material = RootMaterial::ConfirmKit {
                pieces: &pieces,
                passphrase: kit.passphrase.as_ref(),
                carry: &carry,
            };
            vault.run_root_request(owner, request, material)?
        }
        Material::Restore { pieces, passphrase } => {
            let kit = Kit::parse(pieces, passphrase)?;
            let pieces = kit.pieces();
            let secret = RootSecret::Kit {
                pieces: &pieces,
                passphrase: kit.passphrase.as_ref(),
            };
            vault.run_root_request(owner, request, RootMaterial::Restore(secret))?
        }
        Material::Anchor {
            pieces,
            passphrase,
            code,
            ..
        } => {
            let kit = Kit::parse(pieces, passphrase)?;
            let pieces = kit.pieces();
            let enrolment = enrolment.ok_or_else(|| {
                OwnerError::Invalid("an anchoring names the machine's enrolment".to_owned())
            })?;
            let material = RootMaterial::Anchor {
                secret: RootSecret::Kit {
                    pieces: &pieces,
                    passphrase: kit.passphrase.as_ref(),
                },
                request: &enrolment,
                code: code.as_deref().map(request_code).transpose()?,
            };
            vault.run_root_request(owner, request, material)?
        }
    };
    Ok(done)
}

/// One world key, by its world and generation.
#[derive(Debug, Serialize)]
struct KeyView {
    world: String,
    generation: u64,
}

impl From<&WorldKeyId> for KeyView {
    fn from(key: &WorldKeyId) -> Self {
        Self {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }
}

/// A key a door gave no new wrap, and why.
#[derive(Debug, Serialize)]
struct WithheldView {
    #[serde(flatten)]
    key: KeyView,
    reason: &'static str,
}

fn withheld(list: &[(WorldKeyId, Withheld)]) -> Vec<WithheldView> {
    list.iter()
        .map(|(key, why)| WithheldView {
            key: KeyView::from(key),
            reason: match why {
                Withheld::NotMine => "not_mine",
                Withheld::NotReadable => "not_readable",
                Withheld::NotLive => "not_live",
                Withheld::NotPrivate => "not_private",
                Withheld::Conflicted => "conflicted",
                Withheld::Unopenable => "unopenable",
                Withheld::FrontierWide => "frontier_wide",
                Withheld::SignerRemoved => "signer_removed",
            },
        })
        .collect()
}

/// What a re-pin did with each key.
#[derive(Debug, Serialize)]
struct RepinView {
    rewrapped: Vec<KeyView>,
    withheld: Vec<WithheldView>,
    /// Worlds whose settings read differently under the root.
    narrowed: Vec<String>,
    /// The root a second step waits for, 64 hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    awaiting: Option<String>,
}

impl From<&RepinReport> for RepinView {
    fn from(report: &RepinReport) -> Self {
        Self {
            rewrapped: report.rewrapped.iter().map(KeyView::from).collect(),
            withheld: withheld(&report.withheld),
            narrowed: report
                .narrowed
                .iter()
                .map(|narrowed| narrowed.world.to_hex())
                .collect(),
            awaiting: report.awaiting.map(|root| hex(&root.0)),
        }
    }
}

/// What a restore did with each key wrapped to the bound root.
#[derive(Debug, Serialize)]
struct RestoreView {
    /// Opened and readable on this machine.
    usable: Vec<KeyView>,
    /// Kept on another machine: recoverable there, not usable here.
    needs_rehome: Vec<KeyView>,
    withheld: Vec<WithheldView>,
    narrowed: Vec<String>,
}

impl From<&RootRestore> for RestoreView {
    fn from(keys: &RootRestore) -> Self {
        Self {
            usable: keys.usable.iter().map(KeyView::from).collect(),
            needs_rehome: keys.needs_rehome.iter().map(KeyView::from).collect(),
            withheld: withheld(&keys.withheld),
            narrowed: keys
                .narrowed
                .iter()
                .map(|narrowed| narrowed.world.to_hex())
                .collect(),
        }
    }
}

/// One stored piece of an issued kit: its point and its recovery code, for
/// this caller to place. A passphrase home has none.
#[derive(Serialize)]
struct PieceCode {
    x: u8,
    recovery_code: String,
}

/// An issued kit: its public facts and its stored pieces.
#[derive(Serialize)]
struct IssuedView {
    vault_id: String,
    kit_id: String,
    /// The root's fingerprint, 64 hex.
    root: String,
    homes: [PieceHome; 3],
    coverage: KitCoverage,
    pieces: Vec<PieceCode>,
}

/// A confirmed kit: its root is live here.
#[derive(Serialize)]
struct ConfirmedView {
    kit_id: String,
    root: String,
    keys: RepinView,
    /// The kits this one replaced.
    replaced: Vec<String>,
    /// The vault key's `world-kit` escrow wrap; none when the vault has no
    /// key yet.
    vault_key_wrap: Option<WrapView>,
    /// The change committed but a sealed vault's page-seal mirror was not
    /// rewritten: the next sealed open repairs it.
    mirror_pending: bool,
}

/// What the target did, by `done`.
#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "done")]
enum RootWorkReport {
    /// Answered refused: the request is closed.
    Refused { reason: OwnerWorkRefusal },
    /// The activation's kit, issued: its pieces, to this caller only. The
    /// request stays pending until the kit's confirm.
    KitIssued(Box<IssuedView>),
    /// The activation's kit, confirmed: its root is live here.
    KitConfirmed(Box<ConfirmedView>),
    /// The keys wrapped to the bound root, restored from its seed.
    Restored { keys: RestoreView },
    /// The same, from the bound root's kit.
    KitRestored {
        kit_id: String,
        root: String,
        keys: RestoreView,
        /// The kit's passphrase cost is below today's default: issue a new
        /// kit.
        reissue_advised: bool,
    },
    /// The machine, anchored with the bound root's seed; an own-request
    /// anchoring's re-pin.
    Anchored { repin: Option<RepinView> },
}

/// The target's answer: its report, and the engine's words for it.
#[derive(Serialize)]
struct RootWorkAnswer {
    #[serde(flatten)]
    report: RootWorkReport,
    /// `RootWorkDone::text`.
    text: &'static str,
}

impl RootWorkAnswer {
    fn of(vault: &Vault, done: RootWorkDone) -> Self {
        let text = done.text();
        let report = match done {
            RootWorkDone::Refused { reason } => RootWorkReport::Refused { reason },
            RootWorkDone::KitIssued(issued) => RootWorkReport::KitIssued(Box::new(IssuedView {
                vault_id: hex(&issued.vault_id),
                kit_id: kit_id(issued.manifest.kit_id),
                root: hex(&issued.root.0),
                homes: issued.manifest.homes.clone(),
                coverage: issued.manifest.coverage,
                pieces: issued
                    .pieces
                    .iter()
                    .map(|piece| PieceCode {
                        x: piece.x(),
                        recovery_code: piece.recovery_code().reveal().to_owned(),
                    })
                    .collect(),
            })),
            RootWorkDone::KitConfirmed {
                kit,
                mirror_pending,
            } => {
                let vault_id = vault.vault_key_vault_id();
                RootWorkReport::KitConfirmed(Box::new(ConfirmedView {
                    kit_id: kit_id(kit.kit),
                    root: hex(&kit.activated.root.0),
                    keys: RepinView::from(&kit.activated.keys),
                    replaced: kit.replaced.iter().copied().map(kit_id).collect(),
                    vault_key_wrap: kit.escrow.map(|info| WrapView::of(&vault_id, info)),
                    mirror_pending,
                }))
            }
            RootWorkDone::Restored(restore) => RootWorkReport::Restored {
                keys: RestoreView::from(&*restore),
            },
            RootWorkDone::KitRestored(restore) => RootWorkReport::KitRestored {
                kit_id: kit_id(restore.kit),
                root: hex(&restore.root.0),
                keys: RestoreView::from(&restore.keys),
                reissue_advised: restore.reissue_advised,
            },
            RootWorkDone::Anchored(anchored) => RootWorkReport::Anchored {
                repin: anchored.repin.as_ref().map(RepinView::from),
            },
        };
        Self { report, text }
    }
}

/// What a kit grant of pad access did, by kept generation (hex).
#[derive(Debug, Serialize)]
struct PadAccessAnswer {
    /// The machine granted, 32 hex.
    machine: String,
    /// Generations whose grant the home took.
    offered: Vec<String>,
    /// Of those, the ones this install opened its pad object with: only
    /// when the machine granted is this one. An offered grant is not yet
    /// access.
    usable: Vec<String>,
    /// Generations the kit did not open, or whose offer the home refused:
    /// pending with the home for an old reader.
    pending: Vec<String>,
    /// How many are pending.
    pending_count: usize,
}

/// `POST /v1/owner/recovery-kit/pad-access`: the owner's kit grants a
/// machine (this install when none is named) access to every pad object the
/// home keeps, over this install's own connection to its home. The machine
/// must stand as the owner's here; the engine checks it, the owner and the
/// kit's root again for every grant.
async fn pad_access(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: Result<Json<PadAccess>, JsonRejection>,
) -> OwnerReply<PadAccessAnswer> {
    let owner = owner(&auth, &server)?;
    let body = json_payload(payload)?;
    kit_target(&server, &body.target)?;
    let vault = Arc::clone(&server.vault);
    let (seed, recipient, me) = blocking(
        move || -> OwnerResult<(RecoveryRootSeed, PadAdmissionTarget, EntityId)> {
            let kit = Kit::parse(body.pieces, body.passphrase)?;
            let me = vault
                .local_machine()?
                .ok_or_else(|| OwnerError::Refused("this install is no machine yet".to_owned()))?
                .id;
            let machine = match body.machine.as_deref() {
                Some(machine) => entity_id("machine", machine)?,
                None => me,
            };
            let fold = vault.authority_fold()?;
            let trusted = fold.trusted_machine(machine).ok_or_else(|| {
                OwnerError::Refused("the machine does not stand as the owner's here".to_owned())
            })?;
            let recipient = PadAdmissionTarget::of(machine, &trusted.profile.encryption_key);
            Ok((kit.seed(&vault)?, recipient, me))
        },
    )
    .await?;
    let connection = crate::residence_machines::connection(&me).ok_or_else(|| {
        super::owner_error(OwnerError::Refused(
            "this install runs no connection to a home: grant from a machine that syncs with \
             the home"
                .to_owned(),
        ))
    })?;
    let report = connection
        .grant_sealed_bundle_pad_access_with_kit(&owner, &seed, recipient)
        .await
        .map_err(|error| super::owner_error(OwnerError::Refused(error.to_string())))?;
    Ok(Json(PadAccessAnswer {
        machine: recipient.machine.to_hex(),
        offered: generations(&report.offered),
        usable: generations(&report.usable),
        pending_count: report.pending.len(),
        pending: generations(&report.pending),
    }))
}

/// Kept generations as hex.
fn generations(list: &[SealedBundleGeneration]) -> Vec<String> {
    list.iter().map(sealed_generation_hex).collect()
}
