//! The owner's one inbox over both group kinds (FIX 3026): the Dreamer run
//! groups over the pending-consent tray and the vault shape's apply groups
//! (ARCH-0070 `shape:plan-apply`), interleaved on one page, and the owner's
//! answer to a group dispatched by its kind. Each kind keeps its own
//! projection, authority and settlement; this module only orders them and
//! routes the answer.
//!
//! A page orders its groups by source time, newest first (a Dreamer group's
//! earliest open proposal, a shape group's apply start), then by kind, then
//! by group key. Its `next` names the last group served, and the next page
//! resumes past it, so every group stays reachable through the pages.
//! `Vault::inbox_groups_unified` and `Vault::resolve_inbox_group_of_kind`
//! are its call surface.

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::edit_distance::miner::CompilationTarget;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::vault_shape::{ShapeApplyReceipt, ShapeInboxGroup};
use crate::write_envelope::WriteActor;

use super::model::{InboxBulkVerb, InboxBundleResolution, InboxGroup};
use super::root_group::{OpenTray, RunGroups, root_group_card};

/// Which projection a group comes from.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InboxGroupKind {
    /// A Dreamer run's gate-held proposals, keyed by its run-tree root.
    Dreamer,
    /// A vault shape apply's items waiting for the owner's word.
    Shape,
}

impl InboxGroupKind {
    const fn byte(self) -> u8 {
        match self {
            Self::Dreamer => 0,
            Self::Shape => 1,
        }
    }

    const fn of_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Dreamer),
            1 => Some(Self::Shape),
            _ => None,
        }
    }
}

/// One group of the owner's inbox, tagged with its kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnifiedInboxGroup {
    Dreamer { group: InboxGroup },
    Shape { group: ShapeInboxGroup },
}

/// One page of the owner's inbox groups of both kinds, and where the next
/// page resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnifiedInboxGroupPage {
    pub groups: Vec<UnifiedInboxGroup>,
    /// Pass back as the next request's `after`. Absent when no group lies
    /// past this page. A Dreamer group the review dial holds back whole is
    /// passed over, so a later page can come back with no visible group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

/// Where a page ended: the place of the last group it served in the page's
/// order. It resumes the walk and nothing else: it names no authority,
/// expires nothing and counts nothing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnifiedInboxGroupCursor {
    newest: Reverse<u64>,
    kind: InboxGroupKind,
    group_key: String,
}

impl UnifiedInboxGroupCursor {
    fn at(created_at: u64, kind: InboxGroupKind, group_key: &str) -> Self {
        Self {
            newest: Reverse(created_at),
            kind,
            group_key: group_key.to_owned(),
        }
    }

    /// The cursor as a page's `next` carries it: lowercase hex of the source
    /// time (8 bytes), the kind (1 byte) and the group key's bytes.
    #[must_use]
    pub fn to_token(&self) -> String {
        let mut bytes = Vec::with_capacity(9 + self.group_key.len());
        bytes.extend_from_slice(&self.newest.0.to_be_bytes());
        bytes.push(self.kind.byte());
        bytes.extend_from_slice(self.group_key.as_bytes());
        bytes_to_hex_lower(&bytes)
    }

    /// Reads a token [`Self::to_token`] wrote; `None` for anything else.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        if token.len() < 18
            || token.len() % 2 != 0
            || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        let bytes: Vec<u8> = (0..token.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&token[at..at + 2], 16).ok())
            .collect::<Option<_>>()?;
        Some(Self {
            newest: Reverse(u64::from_be_bytes(bytes[..8].try_into().ok()?)),
            kind: InboxGroupKind::of_byte(bytes[8])?,
            group_key: String::from_utf8(bytes[9..].to_vec()).ok()?,
        })
    }
}

/// The host's compilation target for a Dreamer answer, as the wire carries
/// it: the [`CompilationTarget`] shape with a schema derive. Present it is
/// authoritative (ARCH-0056).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum InboxGroupResolveTarget {
    /// Preserve the existing lexical-claim/content-skill-edit chooser.
    Fallback,
    /// Propose a prohibition. Does not install an enforcement rule.
    Ban(String),
    /// Propose an OF-332 style token. Does not supersede an expression head.
    StyleRule(String),
    /// Propose a line for the acting charter. Does not change its authority.
    CharterLine(String),
    /// Propose a brief update. Does not mutate a brief.
    BriefUpdate(String),
}

impl From<&InboxGroupResolveTarget> for CompilationTarget {
    fn from(value: &InboxGroupResolveTarget) -> Self {
        match value {
            InboxGroupResolveTarget::Fallback => Self::Fallback,
            InboxGroupResolveTarget::Ban(text) => Self::Ban(text.clone()),
            InboxGroupResolveTarget::StyleRule(text) => Self::StyleRule(text.clone()),
            InboxGroupResolveTarget::CharterLine(text) => Self::CharterLine(text.clone()),
            InboxGroupResolveTarget::BriefUpdate(text) => Self::BriefUpdate(text.clone()),
        }
    }
}

/// The owner's answer to one inbox group of either kind.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxGroupResolveRequest {
    pub kind: InboxGroupKind,
    /// The group's key, as the page lists it.
    pub group_key: String,
    pub verb: InboxBulkVerb,
    /// Narrows a Dreamer group's bundle to its `new_claim`, `update` or
    /// `conflict` rows. A shape group has no verb classes.
    #[serde(default)]
    pub verb_class: Option<String>,
    /// The host's compilation target for a Dreamer answer. Absent keeps
    /// today's path: no principal, no learning. Present is authoritative
    /// (ARCH-0056). A shape group ignores it.
    #[serde(default)]
    pub target: Option<InboxGroupResolveTarget>,
}

/// What the owner's answer to a group did, by the group's kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InboxGroupResolution {
    /// The Dreamer bundle consent: per-item receipts and one bundle receipt.
    Dreamer { resolution: InboxBundleResolution },
    /// The shape apply's journal after the answer, each item where it stands.
    Shape { receipt: ShapeApplyReceipt },
}

/// A group the page may serve: a Dreamer group is built only when served.
enum Candidate {
    Dreamer,
    Shape(ShapeInboxGroup),
}

impl Vault {
    /// One page of the owner's inbox groups of both kinds, newest first, at
    /// most `limit` visible ones, resuming past `after`. Each Dreamer group
    /// is built complete and surfaced under the persisted review dial, as
    /// [`Vault::inbox_groups`] builds it; each shape group is
    /// [`Vault::inbox_shape_groups`]'s. A `limit` of zero serves one group,
    /// so every page advances.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn inbox_groups_unified(
        &self,
        now: u64,
        limit: usize,
        after: Option<&UnifiedInboxGroupCursor>,
    ) -> Result<UnifiedInboxGroupPage> {
        let limit = limit.max(1);
        let dial = self.inbox_review_dial()?;
        let mut runs = RunGroups::new(self);
        let tray = OpenTray::read(self, &mut runs)?;
        let mut candidates: Vec<(UnifiedInboxGroupCursor, Candidate)> = tray
            .starts()
            .iter()
            .map(|(position, group_key)| {
                (
                    UnifiedInboxGroupCursor::at(
                        position.created_at(),
                        InboxGroupKind::Dreamer,
                        group_key,
                    ),
                    Candidate::Dreamer,
                )
            })
            .collect();
        candidates.extend(self.inbox_shape_groups()?.into_iter().map(|group| {
            (
                UnifiedInboxGroupCursor::at(
                    group.created_at,
                    InboxGroupKind::Shape,
                    &group.group_key,
                ),
                Candidate::Shape(group),
            )
        }));
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        let first = after.map_or(0, |after| {
            candidates.partition_point(|(place, _)| place <= after)
        });
        let total = candidates.len();
        let mut groups = Vec::new();
        for (index, (place, candidate)) in candidates.into_iter().enumerate().skip(first) {
            let group = match candidate {
                Candidate::Dreamer => {
                    match root_group_card(self, &tray, &mut runs, &place.group_key, now, dial)? {
                        Some(group) => UnifiedInboxGroup::Dreamer { group },
                        None => continue,
                    }
                }
                Candidate::Shape(group) => UnifiedInboxGroup::Shape { group },
            };
            groups.push(group);
            if groups.len() == limit {
                return Ok(UnifiedInboxGroupPage {
                    groups,
                    next: (index + 1 < total).then(|| place.to_token()),
                });
            }
        }
        Ok(UnifiedInboxGroupPage { groups, next: None })
    }

    /// The owner's answer to the group `request` names, by its kind: a
    /// Dreamer group's bundle consent ([`Vault::resolve_inbox_group_at`], or
    /// [`Vault::resolve_inbox_group_as_verb_class_at`] when the request
    /// carries a target), or a shape apply's answer
    /// ([`Vault::resolve_shape_inbox_group`]), with the host's slip issuer
    /// when it has one.
    ///
    /// # Errors
    ///
    /// An owner proof that no longer holds, no open group of that kind and
    /// key, a verb class named for a shape group, an invalid learning
    /// target, or a store failure.
    pub fn resolve_inbox_group_of_kind(
        &self,
        owner: &AuthenticatedOwner,
        slips: Option<&HostSlipIssuer>,
        request: &InboxGroupResolveRequest,
        now: u64,
    ) -> Result<InboxGroupResolution> {
        match request.kind {
            InboxGroupKind::Dreamer => {
                let owner_actor = owner.revalidate(self)?;
                let resolution = match request.target.as_ref() {
                    None => self.resolve_inbox_group_at(
                        &request.group_key,
                        request.verb,
                        request.verb_class.as_deref(),
                        now,
                    )?,
                    Some(target) => {
                        let actor = WriteActor::new(owner_actor, EdgeActorClass::Human);
                        let target = CompilationTarget::from(target);
                        self.resolve_inbox_group_as_verb_class_at(
                            actor,
                            &request.group_key,
                            request.verb,
                            request.verb_class.as_deref(),
                            &target,
                            now,
                        )?
                    }
                };
                Ok(InboxGroupResolution::Dreamer { resolution })
            }
            InboxGroupKind::Shape => {
                if request.verb_class.is_some() {
                    return Err(Error::InvalidConfig(
                        "a shape group has no verb classes to narrow".to_owned(),
                    ));
                }
                Ok(InboxGroupResolution::Shape {
                    receipt: self.resolve_shape_inbox_group(
                        owner,
                        slips,
                        &request.group_key,
                        request.verb,
                        now,
                    )?,
                })
            }
        }
    }

    /// Resolves consent as a host-authenticated human over one verb class
    /// and captures that principal's learning evidence atomically, as
    /// [`Vault::resolve_inbox_group_as_at`] does for the whole group.
    /// `target` is an explicit host classification, not permission to
    /// install a rule.
    pub fn resolve_inbox_group_as_verb_class_at(
        &self,
        actor: WriteActor,
        group_key: &str,
        verb: InboxBulkVerb,
        verb_class: Option<&str>,
        target: &CompilationTarget,
        now: u64,
    ) -> Result<InboxBundleResolution> {
        target.validate()?;
        self.resolve_inbox_group_bound_at(group_key, verb, verb_class, now, Some((actor, target)))
    }
}
