//! The canary leak detector, step 1 (Fable's review of verdict 52,
//! 2026-11-10, section 4 idea 1).
//!
//! A canary is one word nobody could guess, seeded into one audience class
//! through public verbs. A scan then reads every surface one actor reaches
//! and looks in each answer for the words that actor's audience excludes,
//! one line per word that got through:
//! `LEAK: <class> canary <word> reached <actor> via <surface>: <excerpt>`.
//!
//! What a scan proves: no canary text outside its audience on the surfaces
//! it read. It proves nothing about metadata (ids, counts, timing), about a
//! surface no scan reads, or about a refused surface: a refusal is recorded
//! as refused, never as read. The positive control ([`CanaryVault::blind`])
//! shows each class reached its own audience somewhere, so an empty scan is
//! never mistaken for a clean one.
//!
//! The words: `canary`, the class's letters, then eight hex of a BLAKE3 hash
//! of the class; lower-case ASCII letters and digits only, so a tokenizer
//! keeps each whole. Each sits in a sentence that also carries
//! [`NEUTRAL_PHRASE`], so the search surfaces ask [`NEUTRAL_QUERY`], which
//! names no canary.
//!
//! The actors ([`CanaryActor`]):
//! - the owner: the vault's embedded owner ([`crate::door::owner`]);
//! - the inside agent: an agent definition with an owner Grant to read every
//!   world, facet, kind band and project at every sensitivity, and a
//!   MessagesRead access grant over the canary relationship space;
//! - the outside agent: an agent definition with an owner Grant to read
//!   public-band rows only, and no access grant.
//!
//! Both agents are agent definitions (`vault.agents.create`), not
//! `Vault::ensure_agent_principal` PERSONs: an in-process read loads a
//! reader's Grants only when it is an AGENT_DEF or a base MACHINE
//! (`claim/scoped_read/agent_grants.rs`, `reader_grants_in`), so a named
//! PERSON principal reads under its Grant only through a credential, which
//! this step does not bind (see [`PENDING`]). A Grant mint signs an owner
//! act that this install must carry, so the seed first roots the vault under
//! a fixed test host issuer and profiles this install, as a self-hosted
//! server's first start does.
//!
//! Step 2, not here: a full Dreamer and Coach pass over the seeded vault with
//! the scripted backend, then the same scans and [`CanaryVault::scan_prompts`]
//! over every prompt it saw.

use std::collections::BTreeSet;
use std::fmt;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::federation::Scope;
use oneiron::feeds::{
    FeedAckRequest, FeedReadRequest, FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest,
};
use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

use crate::clock::FakeClock;
use crate::door;
use crate::fixture::{FixtureError, SeedError, TestVault};
use crate::provider::SeenCall;

/// The words every canary sentence carries, so one query finds them all.
pub const NEUTRAL_PHRASE: &str = "the harbor ledger lists amber lanterns";

/// What the search surfaces ask: the shared words, never a canary word.
pub const NEUTRAL_QUERY: &str = "harbor ledger amber lanterns";

/// The domain every canary word's hash starts with.
const WORD_DOMAIN: &[u8] = b"oneiron-testkit/canary/word/v1\0";
/// The domain the relationship space selector is hashed from.
const SPACE_DOMAIN: &[u8] = b"oneiron-testkit/canary/relationship-space/v1\0";
/// The namespace the owner's keyed canary is put under.
const KV_NAMESPACE: &str = "canary";
/// The key the owner's keyed canary is put under.
const KV_KEY: &str = "probe";
/// The reason every diary read states.
const DIARY_REASON: &str = "canary leak detector visibility check";
/// Rows `vault.claims.list` asks for: far above this fixture's claims, so a
/// full page means the list was cut, which the scan reports.
const CLAIM_LIST_LIMIT: usize = 1000;
/// Results each ranked search asks for.
const SEARCH_LIMIT: usize = 100;
/// Rows per page of an offset or cursor walk.
const PAGE: usize = 100;
/// Rows per room page, the verb's maximum.
const ROOM_PAGE: usize = 256;
/// Entries per feed page, the feed's maximum.
const FEED_PAGE: usize = 256;
/// Pages one walk follows before the scan reports it incomplete.
const MAX_PAGES: usize = 64;
/// Bytes of context an excerpt keeps on each side of a word.
const EXCERPT_BYTES: usize = 48;

/// One reader the fixture seeds and scans as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanaryActor {
    /// The vault's embedded owner.
    Owner,
    /// The agent whose Grant reads every band, with a MessagesRead access
    /// grant over the canary relationship space.
    Inside,
    /// The agent whose Grant reads public-band rows only.
    Outside,
}

impl CanaryActor {
    /// Every actor, in scan order.
    pub const ALL: [Self; 3] = [Self::Owner, Self::Inside, Self::Outside];

    /// The actor's name in leak lines.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Inside => "inside-agent",
            Self::Outside => "outside-agent",
        }
    }
}

impl fmt::Display for CanaryActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A claim's sensitivity band, as `vault.remember` takes it in `scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimBand {
    /// Band 0.
    Public,
    /// Band 1.
    Private,
    /// Band 2, also the band of a claim that names none.
    Sensitive,
    /// Band 3.
    Restricted,
}

impl ClaimBand {
    /// Every band, lowest first.
    pub const ALL: [Self; 4] = [
        Self::Public,
        Self::Private,
        Self::Sensitive,
        Self::Restricted,
    ];

    /// The band's number in a claim's `scope.sensitivity`.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Public => 0,
            Self::Private => 1,
            Self::Sensitive => 2,
            Self::Restricted => 3,
        }
    }
}

/// One audience class a canary is seeded into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanaryClass {
    /// One actor's own diary entry (`self.memory.diary`).
    Diary(CanaryActor),
    /// The owner's keyed value (`vault.kv.put`).
    OwnerKeyValue,
    /// An owner claim in one sensitivity band (`vault.remember`).
    Claim(ClaimBand),
    /// An owner claim with the explicit private flag, at the band a claim
    /// that names none takes (2).
    PrivateFlagClaim,
    /// An owner message whose metadata names the canary relationship space
    /// (`vault.witness`).
    RelationshipMessage,
}

impl CanaryClass {
    /// Every class the fixture seeds, in seeding order.
    pub const SEEDED: [Self; 10] = [
        Self::Diary(CanaryActor::Owner),
        Self::Diary(CanaryActor::Inside),
        Self::Diary(CanaryActor::Outside),
        Self::OwnerKeyValue,
        Self::Claim(ClaimBand::Public),
        Self::Claim(ClaimBand::Private),
        Self::Claim(ClaimBand::Sensitive),
        Self::Claim(ClaimBand::Restricted),
        Self::PrivateFlagClaim,
        Self::RelationshipMessage,
    ];

    /// The class's name in leak lines.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Diary(CanaryActor::Owner) => "diary/owner",
            Self::Diary(CanaryActor::Inside) => "diary/inside-agent",
            Self::Diary(CanaryActor::Outside) => "diary/outside-agent",
            Self::OwnerKeyValue => "kv/owner",
            Self::Claim(ClaimBand::Public) => "claim/public",
            Self::Claim(ClaimBand::Private) => "claim/private",
            Self::Claim(ClaimBand::Sensitive) => "claim/sensitive",
            Self::Claim(ClaimBand::Restricted) => "claim/restricted",
            Self::PrivateFlagClaim => "claim/private-flag",
            Self::RelationshipMessage => "message/relationship",
        }
    }

    /// The class's canary word: `canary`, the class name's letters and
    /// digits, and eight hex of a BLAKE3 hash of the name.
    #[must_use]
    pub fn word(self) -> String {
        let name = self.name();
        let mut hasher = blake3::Hasher::new();
        hasher.update(WORD_DOMAIN);
        hasher.update(name.as_bytes());
        let letters: String = name.chars().filter(char::is_ascii_alphanumeric).collect();
        format!("canary{letters}{}", &hasher.finalize().to_hex()[..8])
    }

    /// The sentence the canary is seeded as: [`NEUTRAL_PHRASE`] and the word.
    #[must_use]
    pub fn text(self) -> String {
        format!("{NEUTRAL_PHRASE} {}.", self.word())
    }

    /// The actors this class's canary may reach.
    #[must_use]
    pub fn audience(self) -> BTreeSet<CanaryActor> {
        use CanaryActor::{Inside, Outside, Owner};
        let actors: &[CanaryActor] = match self {
            Self::Diary(actor) => return BTreeSet::from([actor]),
            Self::Claim(ClaimBand::Public) => &[Owner, Inside, Outside],
            Self::OwnerKeyValue
            | Self::Claim(_)
            | Self::PrivateFlagClaim
            | Self::RelationshipMessage => &[Owner, Inside],
        };
        actors.iter().copied().collect()
    }

    /// Why [`Self::audience`] is what it is, from the engine's read rules.
    #[must_use]
    pub const fn audience_basis(self) -> &'static str {
        match self {
            Self::Diary(_) => {
                "a diary entry is an actor-private NOTE: only its author reads it; owning the vault \
                 is no bypass, and a Grant stands in for no author rule (memory/diary_read.rs, \
                 claim/scoped_read/note_visibility.rs)"
            }
            Self::OwnerKeyValue => {
                "a keyed value is a worldless CLAIM at band 2: its writer reads it through vault.kv, \
                 and the inside agent's every-band Grant covers it on the claim lane"
            }
            Self::Claim(ClaimBand::Public) => "band 0: the owner, and both agents' Grants cover it",
            Self::Claim(_) => {
                "band 1 to 3: the owner, and the inside agent's every-band Grant; the outside \
                 agent's Grant stops at public"
            }
            Self::PrivateFlagClaim => {
                "the private flag binds relationship readers, and a Grant covering the claim stands \
                 in for that check (claim/scoped_read/agent_grants.rs), so the inside agent reads \
                 it; at band 2 the outside agent's public ceiling does not"
            }
            Self::RelationshipMessage => {
                "metadata.rel names the canary space: the owner, and the inside agent through its \
                 MessagesRead access grant and its every-band Grant; the outside agent has neither"
            }
        }
    }

    /// The predicate an owner claim canary is seeded under.
    const fn predicate(self) -> &'static str {
        match self {
            Self::Claim(ClaimBand::Public) => "canary.public",
            Self::Claim(ClaimBand::Private) => "canary.private",
            Self::Claim(ClaimBand::Sensitive) => "canary.sensitive",
            Self::Claim(ClaimBand::Restricted) => "canary.restricted",
            _ => "canary.private_flag",
        }
    }
}

impl fmt::Display for CanaryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An audience class no public door seeds today, and why. Never faked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingClass {
    /// The class, named as [`CanaryClass::name`] would name it.
    pub name: &'static str,
    /// The missing door.
    pub reason: &'static str,
}

/// The audience classes left for a later step, each with its missing door.
pub const PENDING: [PendingClass; 6] = [
    PendingClass {
        name: "kv/agent",
        reason: "an agent's own keyed value: the shipped Gate policy auto-approves claim writes \
                 for class human and one first-party agent only (gate/default_manifest.rs, \
                 actor_ceilings), and vault.kv.put refuses a write the Gate does not auto-approve; \
                 seeding it needs an owner vault.gate.policy.put contribution for the two agents, \
                 whose merge with the shipped manifest is not verified yet",
    },
    PendingClass {
        name: "claim/relationship",
        reason: "a relationship-stamped CLAIM needs a live RELATIONSHIP row, and no public door \
                 mints one (batch/claim_candidate_apply.rs)",
    },
    PendingClass {
        name: "room/project",
        reason: "a project room, private thread or member-restricted conversation: \
                 vault.projects.propose only proposes; confirm, the roster write and room consent \
                 are host or session doors",
    },
    PendingClass {
        name: "vault/shared-member",
        reason: "a completed second member: vault.members.add waits on the invitee's own key \
                 binding, and no one-call public door completes it",
    },
    PendingClass {
        name: "world/device-local",
        reason: "a device-local world: vault.worlds.privacy.set runs only in a run context with \
                 owner and install proof over a live WORLD, and a world-stamped CLAIM mints no WORLD",
    },
    PendingClass {
        name: "reader/credential-agent",
        reason: "a named agent principal (Vault::ensure_agent_principal) reads under its Grant only \
                 through a credential: the in-process read lane loads Grants for AGENT_DEF and \
                 base MACHINE readers only (claim/scoped_read/agent_grants.rs, reader_grants_in), \
                 and the slip ceremony that binds one is not in this step",
    },
];

/// One seeded canary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    /// Its audience class.
    pub class: CanaryClass,
    /// The word a scan looks for.
    pub word: String,
    /// The sentence it was seeded as.
    pub text: String,
    /// The actors it may reach.
    pub audience: BTreeSet<CanaryActor>,
    /// The refs its seeding verb returned, which every scan point-reads.
    pub refs: Vec<String>,
}

impl Canary {
    fn new(class: CanaryClass, refs: Vec<String>) -> Self {
        Self {
            class,
            word: class.word(),
            text: class.text(),
            audience: class.audience(),
            refs,
        }
    }
}

/// One surface's answer, or its refusal, as JSON text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceRead {
    /// The verb or lane read, with its page or point.
    pub surface: String,
    /// The answer as JSON, less any echo of the input; for a refusal, its
    /// message.
    pub text: String,
}

/// Everything one actor's scan read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryScan {
    /// Who read.
    pub actor: CanaryActor,
    /// The surfaces that answered.
    pub seen: Vec<SurfaceRead>,
    /// The surfaces that refused: recorded, never counted as read.
    pub refused: Vec<SurfaceRead>,
    /// Walks cut short: a full claim list, or a cursor past its page cap.
    pub incomplete: Vec<String>,
}

/// Where a canary's audience saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanarySighting {
    /// The canary's class.
    pub class: CanaryClass,
    /// Its word.
    pub word: String,
    /// Each audience actor and surface whose answer held the word.
    pub seen_by: Vec<(CanaryActor, String)>,
}

/// A vault seeded with one canary per feasible audience class, and the ids
/// a scan needs. Seed a fresh one per test with [`Self::seeded`]: its seed
/// binds key custody, so it is never a cached copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryVault {
    owner: EntityId,
    inside: EntityId,
    outside: EntityId,
    inside_grant: String,
    outside_grant: String,
    space: EntityId,
    conversation: String,
    canaries: Vec<Canary>,
}

impl CanaryVault {
    /// A fresh vault for one test, seeded by [`Self::seed`].
    ///
    /// # Errors
    /// The vault cannot be opened, or a seeding door refuses.
    pub fn seeded(name: &str) -> Result<(TestVault, Self), FixtureError> {
        let mut seeded = None;
        let vault = TestVault::seeded(name, |vault, clock| {
            seeded = Some(Self::seed(vault, clock)?);
            Ok(())
        })?;
        let canaries = seeded.ok_or_else(|| {
            FixtureError::Record(format!("the canary seed of {name:?} recorded no canaries"))
        })?;
        Ok((vault, canaries))
    }

    /// Seeds `vault` (opened process-owned) through public doors: roots it
    /// under a fixed test host issuer and profiles this install, makes the
    /// two agents and the owner's Grant to each, then one canary per
    /// [`CanaryClass::SEEDED`] class and the inside agent's MessagesRead
    /// access grant.
    ///
    /// # Errors
    /// A seeding door refuses; the message names the door.
    pub fn seed(vault: &Vault, clock: &FakeClock) -> Result<Self, SeedError> {
        let owner_memory = door::owner(vault).map_err(|error| format!("the owner: {error}"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(|error| format!("the owner: {error}"))?;
        root_vault(vault)?;
        let (inside, inside_grant) = create_agent(
            vault,
            &owner_memory,
            "canary-inside",
            json!({"kind": "all"}),
        )?;
        let (outside, outside_grant) = create_agent(
            vault,
            &owner_memory,
            "canary-outside",
            json!({"kind": "at_most", "value": "public"}),
        )?;
        let inside_memory = vault.memory(inside, EdgeActorClass::Agent);
        let outside_memory = vault.memory(outside, EdgeActorClass::Agent);

        let mut canaries = Vec::new();
        for (actor, memory) in [
            (CanaryActor::Owner, &owner_memory),
            (CanaryActor::Inside, &inside_memory),
            (CanaryActor::Outside, &outside_memory),
        ] {
            let class = CanaryClass::Diary(actor);
            let entry = seed_verb(
                memory,
                "self.memory.diary",
                json!({"content": class.text()}),
            )?;
            canaries.push(Canary::new(class, strings_at(&entry, &["/entry_ref"])));
        }

        let class = CanaryClass::OwnerKeyValue;
        seed_verb(
            &owner_memory,
            "vault.kv.put",
            json!({
                "namespace": [KV_NAMESPACE],
                "key": KV_KEY,
                "value": {"text": class.text()},
                "request_id": "canary-kv-owner",
                "source": "user_stated",
            }),
        )?;
        canaries.push(Canary::new(class, Vec::new()));

        for band in ClaimBand::ALL {
            let class = CanaryClass::Claim(band);
            let receipt = seed_verb(
                &owner_memory,
                "vault.remember",
                claim_input(owner, class, json!({"sensitivity": band.number()})),
            )?;
            canaries.push(Canary::new(
                class,
                strings_at(&receipt, &["/claim_short_id"]),
            ));
        }
        let class = CanaryClass::PrivateFlagClaim;
        let receipt = seed_verb(
            &owner_memory,
            "vault.remember",
            claim_input(owner, class, json!({"private": true})),
        )?;
        canaries.push(Canary::new(
            class,
            strings_at(&receipt, &["/claim_short_id"]),
        ));

        let space = derived_id(SPACE_DOMAIN)?;
        let conversation = vault
            .new_entity_id()
            .map_err(|error| format!("a conversation id: {error}"))?
            .to_hex();
        let class = CanaryClass::RelationshipMessage;
        let witnessed = seed_verb(
            &owner_memory,
            "vault.witness",
            json!({
                "conversation_ref": conversation,
                "messages": [{
                    "author": "user",
                    "message_type": "dialogue",
                    "content": class.text(),
                    "metadata": {"rel": space.to_hex()},
                    "is_visible": true,
                    "order": 0,
                }],
                "occurred_at": clock.now(),
            }),
        )?;
        let mut refs = strings_at(&witnessed, &["/turn_short_id"]);
        if let Some(messages) = witnessed.get("message_short_ids").and_then(Value::as_array) {
            refs.extend(messages.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        canaries.push(Canary::new(class, refs));
        grant_messages_read(vault, clock, inside, space)?;

        Ok(Self {
            owner,
            inside,
            outside,
            inside_grant,
            outside_grant,
            space,
            conversation,
            canaries,
        })
    }

    /// The seeded canaries, in [`CanaryClass::SEEDED`] order.
    #[must_use]
    pub fn canaries(&self) -> &[Canary] {
        &self.canaries
    }

    /// The canary of `class`, if the fixture seeded one.
    #[must_use]
    pub fn canary(&self, class: CanaryClass) -> Option<&Canary> {
        self.canaries.iter().find(|canary| canary.class == class)
    }

    /// `actor`'s entity id: the owner PERSON or the agent's definition.
    #[must_use]
    pub fn actor_id(&self, actor: CanaryActor) -> EntityId {
        match actor {
            CanaryActor::Owner => self.owner,
            CanaryActor::Inside => self.inside,
            CanaryActor::Outside => self.outside,
        }
    }

    /// The owner Grant an agent reads under (its `grant_ref`); `None` for
    /// the owner.
    #[must_use]
    pub fn agent_grant(&self, actor: CanaryActor) -> Option<&str> {
        match actor {
            CanaryActor::Owner => None,
            CanaryActor::Inside => Some(self.inside_grant.as_str()),
            CanaryActor::Outside => Some(self.outside_grant.as_str()),
        }
    }

    /// The relationship space the message canary's metadata names.
    #[must_use]
    pub fn space(&self) -> EntityId {
        self.space
    }

    /// The conversation the message canary was witnessed in (32 hex).
    #[must_use]
    pub fn conversation(&self) -> &str {
        &self.conversation
    }

    /// `actor` as a caller of `vault`.
    #[must_use]
    pub fn memory<'v>(&self, vault: &'v Vault, actor: CanaryActor) -> Memory<'v> {
        let class = match actor {
            CanaryActor::Owner => EdgeActorClass::Human,
            CanaryActor::Inside | CanaryActor::Outside => EdgeActorClass::Agent,
        };
        vault.memory(self.actor_id(actor), class)
    }

    /// The same fixture with `actor` taken out of every audience: what the
    /// detector's self-test scans against.
    #[must_use]
    pub fn excluding(&self, actor: CanaryActor) -> Self {
        let mut narrowed = self.clone();
        for canary in &mut narrowed.canaries {
            canary.audience.remove(&actor);
        }
        narrowed
    }

    /// Reads every surface `actor` reaches through public doors and keeps
    /// each answer as JSON text: `vault.claims.list`; `vault.recall` and
    /// `vault.search.bm25` for [`NEUTRAL_QUERY`]; `vault.kv.search` and
    /// `vault.kv.namespaces` by offset; `self.inbox.list` by cursor;
    /// `vault.rooms.list` and each room's `vault.rooms.messages`, and the
    /// canary conversation's; `self.memory.diary.query` of each actor;
    /// `vault.get` and `vault.hydrate` of every seeded ref; and the change
    /// and settlement feed from its beginning. A diary read and a feed
    /// subscription each leave a row; nothing else writes.
    #[must_use]
    pub fn scan(&self, vault: &Vault, actor: CanaryActor) -> CanaryScan {
        let memory = self.memory(vault, actor);
        let mut reader = Reader {
            memory: &memory,
            words: self
                .canaries
                .iter()
                .map(|canary| canary.word.clone())
                .collect(),
            scan: CanaryScan {
                actor,
                seen: Vec::new(),
                refused: Vec::new(),
                incomplete: Vec::new(),
            },
        };
        if let Some(answer) = reader.read(
            "vault.claims.list",
            "vault.claims.list",
            json!({"limit": CLAIM_LIST_LIMIT}),
        ) {
            let rows = answer
                .pointer("/value")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if rows >= CLAIM_LIST_LIMIT {
                reader
                    .scan
                    .incomplete
                    .push(format!("vault.claims.list: {rows} rows filled the limit"));
            }
        }
        reader.read(
            "vault.recall",
            "vault.recall",
            json!({
                "query": NEUTRAL_QUERY,
                "effort": "light",
                "limit": SEARCH_LIMIT,
                "as_of": vault.now_recorded_at(),
            }),
        );
        reader.read(
            "vault.search.bm25",
            "vault.search.bm25",
            json!({"query": NEUTRAL_QUERY, "limit": SEARCH_LIMIT}),
        );
        reader.walk_offset("vault.kv.search");
        reader.walk_offset("vault.kv.namespaces");
        reader.walk_cursor("self.inbox.list", "self.inbox.list", json!({"limit": PAGE}));
        let rooms: Vec<String> = reader
            .read("vault.rooms.list", "vault.rooms.list", json!({}))
            .and_then(|answer| answer.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        for room in &rooms {
            reader.walk_cursor(
                &format!("vault.rooms.messages {room}"),
                "vault.rooms.messages",
                json!({"room_ref": room, "limit": ROOM_PAGE}),
            );
        }
        reader.walk_cursor(
            "vault.rooms.messages (canary conversation)",
            "vault.rooms.messages",
            json!({"room_ref": self.conversation, "limit": ROOM_PAGE}),
        );
        for whose in CanaryActor::ALL {
            reader.read(
                &format!("self.memory.diary.query ({whose})"),
                "self.memory.diary.query",
                json!({"agent": self.actor_id(whose).to_hex(), "reason": DIARY_REASON}),
            );
        }
        for canary in &self.canaries {
            for reference in &canary.refs {
                reader.read(
                    &format!("vault.get {reference}"),
                    "vault.get",
                    json!({"entity_ref": reference}),
                );
            }
            if !canary.refs.is_empty() {
                reader.read(
                    &format!("vault.hydrate ({})", canary.class),
                    "vault.hydrate",
                    json!({"refs": canary.refs}),
                );
            }
        }
        reader.read(
            "vault.get (canary conversation)",
            "vault.get",
            json!({"entity_ref": self.conversation}),
        );
        reader.read_feed(vault);
        reader.scan
    }

    /// One line per canary `scan` read that its actor's audience excludes,
    /// in answers and in refusal messages alike:
    /// `LEAK: <class> canary <word> reached <actor> via <surface>: <excerpt>`.
    #[must_use]
    pub fn leaks(&self, scan: &CanaryScan) -> Vec<String> {
        let reads = scan
            .seen
            .iter()
            .map(|read| (read, ""))
            .chain(scan.refused.iter().map(|read| (read, " (refusal)")));
        let mut lines = Vec::new();
        for (read, how) in reads {
            for canary in self
                .canaries
                .iter()
                .filter(|canary| !canary.audience.contains(&scan.actor))
            {
                if let Some(at) = read.text.find(canary.word.as_str()) {
                    lines.push(format!(
                        "LEAK: {} canary {} reached {} via {}{how}: {}",
                        canary.class,
                        canary.word,
                        scan.actor,
                        read.surface,
                        excerpt(&read.text, at, canary.word.len())
                    ));
                }
            }
        }
        lines
    }

    /// Scans as `actor` and returns the scan.
    ///
    /// # Panics
    /// When any canary outside `actor`'s audience reached it: one line per
    /// leak ([`Self::leaks`]).
    pub fn assert_no_canary_leak(&self, vault: &Vault, actor: CanaryActor) -> CanaryScan {
        let scan = self.scan(vault, actor);
        let leaks = self.leaks(&scan);
        assert!(
            leaks.is_empty(),
            "{} canary leak(s) as {actor}:\n{}",
            leaks.len(),
            leaks.join("\n")
        );
        scan
    }

    /// The positive control: per canary, each actor inside its audience and
    /// each surface of `scans` where that actor saw it.
    #[must_use]
    pub fn sightings(&self, scans: &[CanaryScan]) -> Vec<CanarySighting> {
        let mut sightings = Vec::new();
        for canary in &self.canaries {
            let mut seen_by = Vec::new();
            for scan in scans
                .iter()
                .filter(|scan| canary.audience.contains(&scan.actor))
            {
                for read in &scan.seen {
                    if read.text.contains(canary.word.as_str()) {
                        seen_by.push((scan.actor, read.surface.clone()));
                    }
                }
            }
            sightings.push(CanarySighting {
                class: canary.class,
                word: canary.word.clone(),
                seen_by,
            });
        }
        sightings
    }

    /// One `BLIND: <class>` line per canary no actor of its audience saw on
    /// any surface of `scans`: for that class the detector proves nothing.
    #[must_use]
    pub fn blind(&self, scans: &[CanaryScan]) -> Vec<String> {
        self.sightings(scans)
            .into_iter()
            .filter(|sighting| sighting.seen_by.is_empty())
            .map(|sighting| {
                format!(
                    "BLIND: {} (canary {} reached no actor of its audience on any surface scanned)",
                    sighting.class, sighting.word
                )
            })
            .collect()
    }

    /// The positive control's sightings.
    ///
    /// # Panics
    /// When any class is blind ([`Self::blind`]).
    pub fn assert_not_blind(&self, scans: &[CanaryScan]) -> Vec<CanarySighting> {
        let blind = self.blind(scans);
        assert!(blind.is_empty(), "{}", blind.join("\n"));
        self.sightings(scans)
    }

    /// The surfaces of `scan` whose answer held the canary of `class`.
    #[must_use]
    pub fn surfaces_seeing(&self, scan: &CanaryScan, class: CanaryClass) -> Vec<String> {
        let Some(canary) = self.canary(class) else {
            return Vec::new();
        };
        scan.seen
            .iter()
            .filter(|read| read.text.contains(canary.word.as_str()))
            .map(|read| read.surface.clone())
            .collect()
    }

    /// One leak line per canary in a prompt a scripted backend saw that
    /// `allowed`, the actors the prompts' destination speaks for, may not all
    /// see. With no actor allowed, every canary is a leak. A call's step id
    /// (or `unscripted`) and its index name the surface.
    #[must_use]
    pub fn scan_prompts(&self, calls: &[SeenCall], allowed: &[CanaryActor]) -> Vec<String> {
        let recipients = if allowed.is_empty() {
            "no actor".to_owned()
        } else {
            allowed
                .iter()
                .map(|actor| actor.name())
                .collect::<Vec<_>>()
                .join("+")
        };
        let mut lines = Vec::new();
        for (index, call) in calls.iter().enumerate() {
            let text = call.body.to_string();
            let step = call.step.as_deref().unwrap_or("unscripted");
            for canary in &self.canaries {
                let permitted = !allowed.is_empty()
                    && allowed.iter().all(|actor| canary.audience.contains(actor));
                if permitted {
                    continue;
                }
                if let Some(at) = text.find(canary.word.as_str()) {
                    lines.push(format!(
                        "LEAK: {} canary {} reached {recipients} via prompt {index} (step {step}): {}",
                        canary.class,
                        canary.word,
                        excerpt(&text, at, canary.word.len())
                    ));
                }
            }
        }
        lines
    }
}

/// One scan in progress: the caller, the words never stripped as an echo,
/// and what it read.
struct Reader<'m, 'v> {
    memory: &'m Memory<'v>,
    words: Vec<String>,
    scan: CanaryScan,
}

impl Reader<'_, '_> {
    /// Runs `verb` with `input` and keeps its answer, less any echo of the
    /// input, or its refusal.
    fn read(&mut self, surface: &str, verb: &str, input: Value) -> Option<Value> {
        match door::invoke(self.memory, verb, input.clone()) {
            Ok(answer) => {
                let text = strip_echo(&answer.to_string(), &input, &self.words);
                self.scan.seen.push(SurfaceRead {
                    surface: surface.to_owned(),
                    text,
                });
                Some(answer)
            }
            Err(error) => {
                self.refuse(surface, error.to_string());
                None
            }
        }
    }

    fn refuse(&mut self, surface: &str, message: String) {
        self.scan.refused.push(SurfaceRead {
            surface: surface.to_owned(),
            text: message,
        });
    }

    /// Pages `verb` by `offset` until a page comes back short.
    fn walk_offset(&mut self, verb: &str) {
        let mut offset = 0;
        for _ in 0..MAX_PAGES {
            let Some(answer) = self.read(
                &format!("{verb} offset {offset}"),
                verb,
                json!({"limit": PAGE, "offset": offset}),
            ) else {
                return;
            };
            let rows = answer.as_array().map_or(0, Vec::len);
            if rows < PAGE {
                return;
            }
            offset += rows;
        }
        self.scan
            .incomplete
            .push(format!("{verb}: more than {MAX_PAGES} pages"));
    }

    /// Pages `verb` from `first`, passing each `next_after` back as `after`,
    /// until the cursor ends or repeats.
    fn walk_cursor(&mut self, label: &str, verb: &str, first: Value) {
        let mut after: Option<String> = None;
        for page in 0..MAX_PAGES {
            let mut input = first.clone();
            if let (Some(after), Some(fields)) = (&after, input.as_object_mut()) {
                fields.insert("after".to_owned(), json!(after));
            }
            let Some(answer) = self.read(&format!("{label} page {page}"), verb, input) else {
                return;
            };
            match answer.get("next_after").and_then(Value::as_str) {
                Some(next) if after.as_deref() != Some(next) => after = Some(next.to_owned()),
                _ => return,
            }
        }
        self.scan
            .incomplete
            .push(format!("{label}: more than {MAX_PAGES} pages"));
    }

    /// Subscribes this caller's read lane to the change and settlement feed
    /// from its beginning, then reads and acknowledges every page.
    fn read_feed(&mut self, vault: &Vault) {
        const SURFACE: &str = "feed (changes, settlements)";
        let lane = match self.memory.read_key() {
            Ok(key) => vault.scoped_read(key),
            Err(error) => {
                self.refuse(SURFACE, error.to_string());
                return;
            }
        };
        let request = FeedSubscribeRequest {
            selector: FeedSelector {
                sources: vec![FeedSource::Changes, FeedSource::Settlements],
                kinds: Vec::new(),
                entity_types: Vec::new(),
                predicates: Vec::new(),
            },
            start: FeedStart::Beginning,
        };
        let subscription = match vault.feed_subscribe(&lane, &request) {
            Ok(subscription) => subscription.subscription,
            Err(error) => {
                self.refuse(SURFACE, error.to_string());
                return;
            }
        };
        for page in 0..MAX_PAGES {
            let read = FeedReadRequest {
                subscription,
                limit: Some(FEED_PAGE),
            };
            let answer = match vault.feed_read(&lane, &read) {
                Ok(answer) => answer,
                Err(error) => {
                    self.refuse(SURFACE, error.to_string());
                    return;
                }
            };
            self.scan.seen.push(SurfaceRead {
                surface: format!("feed page {page}"),
                text: serde_json::to_string(&answer).unwrap_or_default(),
            });
            if !answer.through.is_empty() {
                let ack = FeedAckRequest {
                    subscription,
                    through: answer.through.clone(),
                };
                if let Err(error) = vault.feed_ack(&lane, &ack) {
                    self.refuse(SURFACE, error.to_string());
                    return;
                }
            }
            if !answer.more {
                return;
            }
        }
        self.scan
            .incomplete
            .push(format!("{SURFACE}: more than {MAX_PAGES} pages"));
    }
}

/// Runs a seeding verb as `caller`; a refusal names the verb.
fn seed_verb(caller: &Memory<'_>, verb: &str, input: Value) -> Result<Value, SeedError> {
    door::invoke(caller, verb, input)
        .map_err(|error| SeedError::from(format!("canary seed ({verb}): {error}")))
}

/// Attaches the kit's one test host ([`crate::dreamer::attach_test_host`]),
/// so the vault carries the owner's Grant acts and a later Dreamer pass over
/// it presents the same issuer.
fn root_vault(vault: &Vault) -> Result<(), SeedError> {
    crate::dreamer::attach_test_host(vault).map_err(|error| format!("the test host: {error}"))?;
    Ok(())
}

/// Makes one agent definition and the owner's read Grant to it, reading
/// every world, facet, kind band and project up to `sensitivity`. Returns the
/// agent and the Grant's ref.
fn create_agent(
    vault: &Vault,
    owner: &Memory<'_>,
    agent_id: &str,
    sensitivity: Value,
) -> Result<(EntityId, String), SeedError> {
    let id = vault
        .new_entity_id()
        .map_err(|error| format!("{agent_id}: an id: {error}"))?;
    seed_verb(
        owner,
        "vault.agents.create",
        json!({
            "agent_def_ref": id.to_hex(),
            "definition": {
                "agent_id": agent_id,
                "desc": "a reader the canary leak detector scans as",
                "version": "1",
            },
        }),
    )?;
    let minted = seed_verb(
        owner,
        "vault.agents.grants.mint",
        json!({
            "agent": id.to_hex(),
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": ["read"]},
                "sensitivity": sensitivity,
            },
        }),
    )?;
    let grant = minted
        .pointer("/grant/grant_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{agent_id}: the mint named no grant_ref: {minted}"))?
        .to_owned();
    Ok((id, grant))
}

/// The owner's `vault.remember` input for a claim canary of `class`.
fn claim_input(subject: EntityId, class: CanaryClass, scope: Value) -> Value {
    json!({
        "predicate": class.predicate(),
        "subject_ref": subject.to_hex(),
        "value": class.text(),
        "confidence": 0.9,
        "source": "user_stated",
        "scope": scope,
    })
}

/// The inside agent's MessagesRead access grant over `space`, read verb
/// only, from now on.
fn grant_messages_read(
    vault: &Vault,
    clock: &FakeClock,
    reader: EntityId,
    space: EntityId,
) -> Result<(), SeedError> {
    let id = vault
        .new_entity_id()
        .map_err(|error| format!("an access grant id: {error}"))?;
    let grant = AccessGrant {
        authority_scope: Scope {
            verbs: ["read".to_owned()].into_iter().collect(),
            ..Scope::top()
        },
        principal_ref: reader,
        scope: AccessGrantScope::Messages { space_ref: space },
        capability: AccessGrantCapability::MessagesRead,
        status: AccessGrantStatus::Active,
        created_at: clock.now(),
        revoked_at: None,
        expires_at: None,
        companion_bounds: None,
    };
    vault
        .create_access_grant(&id, &grant)
        .map_err(|error| SeedError::from(format!("the MessagesRead access grant: {error}")))
}

/// A fixed entity id from the first sixteen bytes of `domain`'s BLAKE3 hash.
fn derived_id(domain: &[u8]) -> Result<EntityId, SeedError> {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&blake3::hash(domain).as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|error| SeedError::from(format!("a derived id: {error}")))
}

/// The strings at `pointers` in `value`, skipping any absent.
fn strings_at(value: &Value, pointers: &[&str]) -> Vec<String> {
    pointers
        .iter()
        .filter_map(|pointer| value.pointer(pointer))
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// `text` with every string of `input` blanked out, so an answer that echoes
/// its query is not read as a sighting. A string that is part of a canary
/// word is kept, so no word is ever cut.
fn strip_echo(text: &str, input: &Value, words: &[String]) -> String {
    let mut echoes = Vec::new();
    string_leaves(input, &mut echoes);
    let mut text = text.to_owned();
    for echo in echoes {
        if echo.is_empty() || words.iter().any(|word| word.contains(echo.as_str())) {
            continue;
        }
        text = text.replace(echo.as_str(), " ");
    }
    text
}

fn string_leaves(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| string_leaves(item, out)),
        Value::Object(fields) => fields.values().for_each(|item| string_leaves(item, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Up to [`EXCERPT_BYTES`] either side of the `len` bytes at `at`, cut on
/// character boundaries.
fn excerpt(text: &str, at: usize, len: usize) -> String {
    let mut start = at.saturating_sub(EXCERPT_BYTES);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = at
        .saturating_add(len)
        .saturating_add(EXCERPT_BYTES)
        .min(text.len());
    while !text.is_char_boundary(end) {
        end += 1;
    }
    text[start..end].to_owned()
}
