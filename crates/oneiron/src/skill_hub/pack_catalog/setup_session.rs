//! Source-bound guided pack setup (OF-378). A session binds one owner
//! principal to one exact pack source and the permission card that source
//! computes. It keeps refs only: the custody records the owner stored
//! credentials under, the consent receipts of the permissions the owner
//! allowed, the connector keys bound to connections, and each connection's
//! latest check. Installing grants nothing and a session activates nothing;
//! the pack's own qualification still decides Active. A built-in pack's
//! qualification is its checked setup connection, so the check that turns it
//! Verified qualifies it in the same flow. The setup skill is read from the
//! exact source, so a Candidate is set up before it qualifies.
//!
//! Model setup is not here: first-run model setup is the server's one
//! shared operation (`commands::init::setup_models`, ARCH-0036), and a
//! pack's setup covers the pack's own connections. Agents reach this setup
//! through the `vault.packs.setup.*` verbs, which never answer `allow`.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::admission::{PACK_CANDIDATE, pack_permissions};
use super::setup::{PackSetup, PackSetupConnection, PackSetupSecret};
use super::{PackInstallReceipt, PackInstallStatus, PackPermissions, PackSource, invalid};
use crate::consent::AuthenticatedOwner;
use crate::secret_custody::{
    SecretCustodyStatus, read_secret_custody_in_txn, resolve_secret_ref_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault, error::Result};

/// One owner's session over one exact source, keyed by pack name, content
/// hash and principal digest.
const PACK_SETUP: SideTable<String, PackSetupSession, Named> =
    SideTable::new(&side_table::SKILL_HUB_PACK_SETUP);
/// The Candidate catalog a by-name lookup reads before it gives up.
const MAX_CANDIDATE_SCAN: usize = 4096;
/// Most sessions one exact source may hold, one per owner principal.
const MAX_SOURCE_SESSIONS: usize = 64;
/// The setup skill text a session serves, at most.
const MAX_INSTRUCTIONS_BYTES: usize = 16 * 1024;

/// The stored session: refs and check results, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupSession {
    pub session_id: String,
    pub principal_ref: String,
    pub pack_name: String,
    pub source_id: String,
    pub content_hash: String,
    /// Digest of the permission card the exact source computes. A card that
    /// no longer matches ends the session.
    pub permissions_hash: String,
    pub custody: Vec<PackSetupCustodyRef>,
    pub grants: Vec<PackSetupGrantRef>,
    pub keys: Vec<PackSetupKeyRef>,
    pub checks: Vec<PackSetupCheckRecord>,
    pub opened_at: u64,
    pub updated_at: u64,
}

/// The custody record a declared credential name resolved to when pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupCustodyRef {
    pub connection: String,
    pub secret: String,
    pub custody_id: String,
    pub generation: u32,
}

/// The standing consent grant one allowed permission minted, and the Gate
/// decision its receipt was recorded under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupGrantRef {
    pub connection: String,
    pub permission: String,
    pub grant_ref: String,
    pub decision_id: String,
    pub granted_at: u64,
}

/// A registered connector key bound to a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupKeyRef {
    pub connection: String,
    pub key_id: String,
}

/// One connection's latest check, over the grants, custody and key it ran
/// against (`basis`). A basis that moved makes the result stale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupCheckRecord {
    pub connection: String,
    pub verified: bool,
    pub account: Option<String>,
    pub evidence: Option<String>,
    pub reason: Option<String>,
    pub basis: String,
    pub checked_at: u64,
}

/// What the owner sees: the declaration, the instructions, the whole
/// permission card and every connection's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupView {
    pub session_id: String,
    pub pack_name: String,
    pub description: String,
    pub version: String,
    pub source_id: String,
    pub content_hash: String,
    pub status: PackInstallStatus,
    pub setup: PackSetup,
    /// The setup skill's body from the exact source.
    pub instructions: String,
    /// Every power the source asks for, granted by nothing here.
    pub permissions: PackPermissions,
    pub connections: Vec<PackSetupConnectionState>,
    /// Every connection is ready.
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupConnectionState {
    pub id: String,
    pub secrets: Vec<PackSetupSecretState>,
    pub permissions: Vec<PackSetupPermissionState>,
    pub connector_key: Option<String>,
    pub check: PackSetupCheck,
    /// Credentials stored, required permissions allowed, and a check that
    /// passed against exactly these.
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupSecretState {
    pub name: String,
    /// A live custody record holds the name.
    pub stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupPermissionState {
    pub id: String,
    pub granted: bool,
    pub grant_ref: Option<String>,
    pub decision_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PackSetupCheck {
    Unchecked,
    Verified {
        account: String,
        evidence: String,
        checked_at: u64,
    },
    Failed {
        reason: String,
        checked_at: u64,
    },
    /// A grant, credential or key moved after the check.
    Stale {
        checked_at: u64,
    },
}

/// One owner answer. A credential's value never passes here: it goes to the
/// owner secrets door, and this answer pins the custody record it made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackSetupAnswer {
    SecretStored {
        connection: String,
        secret: String,
    },
    /// The owner reviewed the connection's permissions and allowed exactly
    /// these. Each one mints a standing consent grant with its Gate receipt;
    /// one withdrawn is revoked through the consent door.
    Allow {
        connection: String,
        permissions: Vec<String>,
    },
    /// A registered connector key governs the connection; its real
    /// qualification becomes the connection's check.
    BindKey {
        connection: String,
        key: String,
    },
}

/// One session's exact frame, read in one snapshot: the receipt, the live
/// source it names, its setup and its permission card digest.
pub(crate) struct PackSetupBinding {
    pub(crate) key: String,
    pub(crate) principal_ref: String,
    pub(crate) receipt: PackInstallReceipt,
    pub(crate) source: PackSource,
    pub(crate) setup: PackSetup,
    pub(crate) permissions_hash: String,
}

impl Vault {
    /// Opens, or resumes, the owner's setup of one pack: the Active source by
    /// name, else its one Candidate, or exactly the source `content_hash`
    /// names. Setup grants nothing by opening.
    pub fn prepare_pack_setup(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
    ) -> Result<PackSetupView> {
        self.with_write_txn_grouped(|txn| {
            let principal = owner.principal_ref_in_txn(self, txn)?.to_owned();
            let binding = self.bind_pack_setup_in_txn(txn, &principal, pack, content_hash)?;
            let held = PACK_SETUP.get(&self.store, txn, &binding.key)?;
            let mut session = match held {
                Some(session) if session.permissions_hash == binding.permissions_hash => session,
                // A card that moved under the same key starts over: nothing
                // the old session allowed carries to powers it never showed.
                _ => {
                    let now = crate::unix_seconds_now();
                    PackSetupSession {
                        session_id: blake3::hash(binding.key.as_bytes()).to_hex()[..32].to_owned(),
                        principal_ref: binding.principal_ref.clone(),
                        pack_name: binding.receipt.pack_name.clone(),
                        source_id: binding.receipt.source_id.clone(),
                        content_hash: binding.receipt.content_hash.clone(),
                        permissions_hash: binding.permissions_hash.clone(),
                        custody: Vec::new(),
                        grants: Vec::new(),
                        keys: Vec::new(),
                        checks: Vec::new(),
                        opened_at: now,
                        updated_at: now,
                    }
                }
            };
            self.put_pack_setup_in_txn(txn, &binding, &mut session)?;
            self.pack_setup_view_in_txn(txn, &binding, &session)
        })
    }

    /// The owner's setup of one pack as it stands.
    pub fn pack_setup(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
    ) -> Result<PackSetupView> {
        let principal = owner.principal_ref_for_read(self)?.to_owned();
        let txn = self.store.env.read_txn()?;
        let binding = self.bind_pack_setup_in_txn(&txn, &principal, pack, content_hash)?;
        let session = self.require_pack_setup_in_txn(&txn, &binding)?;
        self.pack_setup_view_in_txn(&txn, &binding, &session)
    }

    /// Takes one owner answer. Permissions and connector keys go through the
    /// connector-key setup door; a stored credential is pinned here.
    pub fn answer_pack_setup(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        answer: &PackSetupAnswer,
    ) -> Result<PackSetupView> {
        match answer {
            PackSetupAnswer::SecretStored { connection, secret } => {
                self.pin_pack_setup_custody(owner, pack, content_hash, connection, secret)
            }
            PackSetupAnswer::Allow {
                connection,
                permissions,
            } => self.allow_pack_connection(owner, pack, content_hash, connection, permissions),
            PackSetupAnswer::BindKey { connection, key } => {
                self.bind_pack_connection_key(owner, pack, content_hash, connection, key)
            }
        }
    }

    fn pin_pack_setup_custody(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        connection: &str,
        secret: &str,
    ) -> Result<PackSetupView> {
        let effector = {
            let principal = owner.principal_ref_for_read(self)?.to_owned();
            let txn = self.store.env.read_txn()?;
            let binding = self.bind_pack_setup_in_txn(&txn, &principal, pack, content_hash)?;
            declared_secret(&binding.setup, connection, secret)?
                .effector
                .clone()
        };
        // The value door's own admission, read before the writer opens: live,
        // bound for read to the effector the pack uses, under door policy.
        self.check_secret_at_door(secret, &effector)?;
        self.with_write_txn_grouped(|txn| {
            let principal = owner.principal_ref_in_txn(self, txn)?.to_owned();
            let binding = self.bind_pack_setup_in_txn(txn, &principal, pack, content_hash)?;
            let mut session = self.require_pack_setup_in_txn(txn, &binding)?;
            let declared = declared_secret(&binding.setup, connection, secret)?;
            if live_custody_in_txn(&self.store, txn, &declared.name)?.is_none() {
                return Err(invalid(
                    "no live custody holds that name; store it through the owner secrets door",
                ));
            }
            pin_custody_in_txn(&self.store, txn, connection, declared, &mut session)?;
            self.put_pack_setup_in_txn(txn, &binding, &mut session)?;
            self.pack_setup_view_in_txn(txn, &binding, &session)
        })
    }

    /// Resolves the exact frame a session is bound to and refuses drift: a
    /// source that is no longer live, a receipt that names another source,
    /// or a permission card the source no longer computes.
    pub(crate) fn bind_pack_setup_in_txn(
        &self,
        txn: &RoTxn<'_>,
        principal: &str,
        pack: &str,
        content_hash: Option<&str>,
    ) -> Result<PackSetupBinding> {
        let receipt = self.pack_setup_receipt_in_txn(txn, pack, content_hash)?;
        let source_id = EntityId::from_hex(&receipt.source_id)?;
        let source = self
            .pack_source_in_txn(txn, &source_id)?
            .ok_or_else(|| invalid("the pack source is no longer live"))?;
        if source.manifest.name != pack
            || source.content_hash().to_hex() != receipt.content_hash
            || source.manifest.kind != receipt.kind
            || source.manifest.adapter != receipt.adapter
        {
            return Err(invalid("installed source identity drift"));
        }
        let setup = source
            .manifest
            .setup
            .clone()
            .ok_or_else(|| invalid("the pack declares no setup"))?;
        // The same drift admission refuses at install: the receipt's card
        // must be the card this exact source computes.
        let permissions_hash = permission_snapshot(&pack_permissions(&source, None)?)?;
        if permission_snapshot(&receipt.permissions)? != permissions_hash {
            return Err(invalid("pack permission card drift"));
        }
        Ok(PackSetupBinding {
            key: session_key(pack, &receipt.content_hash, principal),
            principal_ref: principal.to_owned(),
            receipt,
            source,
            setup,
            permissions_hash,
        })
    }

    pub(crate) fn pack_setup_receipt_in_txn(
        &self,
        txn: &RoTxn<'_>,
        pack: &str,
        content_hash: Option<&str>,
    ) -> Result<PackInstallReceipt> {
        if let Some(installed) = self.installed_pack_in_txn(txn, pack)?
            && content_hash.is_none_or(|hash| hash == installed.content_hash)
        {
            return Ok(installed);
        }
        if let Some(hash) = content_hash {
            return PACK_CANDIDATE
                .get(&self.store, txn, &hash.to_owned())?
                .filter(|receipt| receipt.pack_name == pack)
                .ok_or_else(|| invalid("no source of this pack has that content hash"));
        }
        let mut found = None;
        for (seen, entry) in PACK_CANDIDATE.iter_from(&self.store, txn, &[])?.enumerate() {
            if seen >= MAX_CANDIDATE_SCAN {
                return Err(invalid("candidate pack catalog exceeds bound"));
            }
            let (_, receipt) = entry?;
            if receipt.pack_name == pack && found.replace(receipt).is_some() {
                return Err(invalid(
                    "several Candidate sources of this pack wait; name one by its content hash",
                ));
            }
        }
        found.ok_or_else(|| invalid("the pack is neither installed nor a Candidate"))
    }

    /// The bound session, or a refusal: none opened, or one whose card moved.
    pub(crate) fn require_pack_setup_in_txn(
        &self,
        txn: &RoTxn<'_>,
        binding: &PackSetupBinding,
    ) -> Result<PackSetupSession> {
        let session = PACK_SETUP
            .get(&self.store, txn, &binding.key)?
            .ok_or_else(|| invalid("no setup session for this pack; prepare it first"))?;
        if session.permissions_hash != binding.permissions_hash
            || session.content_hash != binding.receipt.content_hash
            || session.principal_ref != binding.principal_ref
        {
            return Err(invalid("pack permission card drift; prepare setup again"));
        }
        Ok(session)
    }

    pub(crate) fn put_pack_setup_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        binding: &PackSetupBinding,
        session: &mut PackSetupSession,
    ) -> Result<()> {
        session.updated_at = crate::unix_seconds_now();
        PACK_SETUP.put(&self.store, txn, &binding.key, session)
    }

    /// Every session over one exact source, for the use-time check.
    pub(crate) fn pack_setup_sessions_in_txn(
        &self,
        txn: &RoTxn<'_>,
        pack: &str,
        content_hash: &str,
    ) -> Result<Vec<PackSetupSession>> {
        let prefix = format!("{pack}/{content_hash}/");
        let mut sessions = Vec::new();
        for entry in PACK_SETUP.iter_from(&self.store, txn, prefix.as_bytes())? {
            if sessions.len() >= MAX_SOURCE_SESSIONS {
                return Err(invalid("pack setup sessions exceed bound"));
            }
            sessions.push(entry?.1);
        }
        Ok(sessions)
    }

    pub(crate) fn pack_setup_view_in_txn(
        &self,
        txn: &RoTxn<'_>,
        binding: &PackSetupBinding,
        session: &PackSetupSession,
    ) -> Result<PackSetupView> {
        let mut connections = Vec::with_capacity(binding.setup.connections.len());
        for connection in &binding.setup.connections {
            connections.push(self.connection_state_in_txn(txn, connection, session)?);
        }
        let manifest = binding.source.manifest();
        Ok(PackSetupView {
            session_id: session.session_id.clone(),
            pack_name: manifest.name.clone(),
            description: manifest.description.clone(),
            version: manifest.version.clone(),
            source_id: binding.receipt.source_id.clone(),
            content_hash: binding.receipt.content_hash.clone(),
            status: binding.receipt.status,
            setup: binding.setup.clone(),
            instructions: setup_instructions(&binding.source, &binding.setup)?,
            permissions: binding.receipt.permissions.clone(),
            ready: connections.iter().all(|connection| connection.ready),
            connections,
        })
    }

    /// One connection as it stands now: what is stored, allowed and bound,
    /// and whether its last check still holds.
    pub(crate) fn connection_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
        connection: &PackSetupConnection,
        session: &PackSetupSession,
    ) -> Result<PackSetupConnectionState> {
        let mut secrets = Vec::with_capacity(connection.secrets.len());
        for secret in &connection.secrets {
            secrets.push(PackSetupSecretState {
                name: secret.name.clone(),
                stored: live_custody_in_txn(&self.store, txn, &secret.name)?.is_some(),
            });
        }
        let mut permissions = Vec::with_capacity(connection.permissions.len());
        for permission in &connection.permissions {
            let grant = session.grants.iter().find(|grant| {
                grant.connection == connection.id && grant.permission == permission.id
            });
            let granted = match grant {
                Some(grant) => crate::consent::standing_grant_is_active_in_txn(
                    &self.store,
                    txn,
                    &grant.grant_ref,
                )?,
                None => false,
            };
            let live = grant.filter(|_| granted);
            permissions.push(PackSetupPermissionState {
                id: permission.id.clone(),
                granted,
                grant_ref: live.map(|grant| grant.grant_ref.clone()),
                decision_id: live.map(|grant| grant.decision_id.clone()),
            });
        }
        let basis = self.pack_connection_basis_in_txn(txn, connection, session)?;
        let check = match session
            .checks
            .iter()
            .find(|check| check.connection == connection.id)
        {
            None => PackSetupCheck::Unchecked,
            Some(record) if record.basis != basis => PackSetupCheck::Stale {
                checked_at: record.checked_at,
            },
            Some(record) if record.verified => PackSetupCheck::Verified {
                account: record.account.clone().unwrap_or_default(),
                evidence: record.evidence.clone().unwrap_or_default(),
                checked_at: record.checked_at,
            },
            Some(record) => PackSetupCheck::Failed {
                reason: record.reason.clone().unwrap_or_default(),
                checked_at: record.checked_at,
            },
        };
        let allowed = connection.required().all(|required| {
            permissions
                .iter()
                .any(|state| state.id == required.id && state.granted)
        });
        let ready = allowed
            && secrets.iter().all(|secret| secret.stored)
            && matches!(check, PackSetupCheck::Verified { .. });
        Ok(PackSetupConnectionState {
            id: connection.id.clone(),
            secrets,
            permissions,
            connector_key: session
                .keys
                .iter()
                .find(|key| key.connection == connection.id)
                .map(|key| key.key_id.clone()),
            check,
            ready,
        })
    }
}

/// Pins the custody record each declared credential of `connection`
/// resolves to now, replacing an older pin of the same name.
pub(crate) fn pin_connection_custody_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    connection: &PackSetupConnection,
    session: &mut PackSetupSession,
) -> Result<()> {
    for secret in &connection.secrets {
        pin_custody_in_txn(store, txn, &connection.id, secret, session)?;
    }
    Ok(())
}

fn pin_custody_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    connection: &str,
    secret: &PackSetupSecret,
    session: &mut PackSetupSession,
) -> Result<()> {
    session
        .custody
        .retain(|pin| !(pin.connection == connection && pin.secret == secret.name));
    if let Some((id, generation)) = live_custody_in_txn(store, txn, &secret.name)? {
        session.custody.push(PackSetupCustodyRef {
            connection: connection.to_owned(),
            secret: secret.name.clone(),
            custody_id: id.to_hex(),
            generation,
        });
    }
    Ok(())
}

/// The live custody record a name resolves to, with its rotation
/// generation; `None` when no Active record holds the name. Never a value.
pub(crate) fn live_custody_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    name: &str,
) -> Result<Option<(EntityId, u32)>> {
    let Some(id) = resolve_secret_ref_in_txn(store, txn, name)? else {
        return Ok(None);
    };
    Ok(read_secret_custody_in_txn(store, txn, &id)?
        .filter(|record| record.status == SecretCustodyStatus::Active)
        .map(|record| (id, record.rotation_generation)))
}

fn declared_secret<'a>(
    setup: &'a PackSetup,
    connection: &str,
    secret: &str,
) -> Result<&'a PackSetupSecret> {
    setup
        .connection(connection)
        .and_then(|connection| connection.secrets.iter().find(|item| item.name == secret))
        .ok_or_else(|| invalid("the connection declares no such credential"))
}

fn session_key(pack: &str, content_hash: &str, principal: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.pack-setup.principal.v1");
    hasher.update(principal.as_bytes());
    let digest = hasher.finalize().to_hex();
    format!("{pack}/{content_hash}/{}", &digest[..32])
}

/// The powers a card asks for, without what it widens over a prior install:
/// one source always computes the same snapshot.
fn permission_snapshot(card: &PackPermissions) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        &card.bundled_skills,
        &card.grants,
        &card.wakes,
        &card.hooks,
        &card.organs,
        &card.section_verbs,
        &card.section_authorities,
    ))
    .map_err(|_| invalid("permission card encoding"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// The setup skill's body, its frontmatter dropped, bounded.
fn setup_instructions(source: &PackSource, setup: &PackSetup) -> Result<String> {
    let path = setup.skill_path();
    let file = source
        .files()
        .iter()
        .find(|file| file.path == path)
        .ok_or_else(|| invalid("setup skill is absent from the pack source"))?;
    let text =
        std::str::from_utf8(&file.content).map_err(|_| invalid("setup skill is not UTF-8"))?;
    let body = match super::super::folder::source_frontmatter(text)? {
        Some(front) => &text["---\n".len() + front.len() + "\n---\n".len()..],
        None => text,
    };
    let mut body = body.trim().to_owned();
    if body.len() > MAX_INSTRUCTIONS_BYTES {
        let mut cut = MAX_INSTRUCTIONS_BYTES;
        while !body.is_char_boundary(cut) {
            cut -= 1;
        }
        body.truncate(cut);
    }
    Ok(body)
}
