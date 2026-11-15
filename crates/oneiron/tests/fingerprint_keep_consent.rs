//! K-proof (oracle) for PLAN-UC-04 stage 3.1: the consent bound and effect digests keep
//! their bytes.
//!
//! `GrantBound::digest` (`oneiron-store`) and `ComposedEffect::digest` now start their
//! BLAKE3 through the fingerprint crate's K door (`purposes::consent::BOUND_DIGEST` and
//! `EFFECT_DIGEST`). The bound digest's hex is each standing grant's row key and its
//! receipt's `diff_handle`; approve-once markers and code consent waits store the effect
//! digest. So both must give main's bytes for every value. `base` below holds main's
//! lines at 55e034509eb1, copied by range (each range is named above its copy; the
//! generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_consent_keep_oracle.py`) and
//! differing from them only in indentation. The copies sit on two views, `Bound` and
//! `Effect`, which reach the same fields through public paths, so each `self.` in the
//! copied bodies is unchanged, and the effect copy hashes its requirements with the bound
//! copy.
//!
//! The fixtures build bounds from their public fields, past the constructors'
//! normalization, so the table holds empty strings, empty lists, unsorted and repeated
//! members, `None` and `u64::MAX`, and crossed domains. The digest reads every field as
//! it stands, so each of those rows is a value a future caller could hash.

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::Result;
use oneiron::consent::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, BoundClass, BoundEnvelope,
    BoundSubject, CatastropheClass, ComposedEffect, DisclosureClass, DisclosureEnvelope,
    EffectFacts, EffectPlace, GrantBound, UndoFidelity,
};
use oneiron_authority::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's. main's copied lines
// keep their `pub`, which this private module cannot reach.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base {
    use oneiron::consent::{
        BoundEnvelope, BoundSubject, CatastropheClass, ComposedEffect, EffectDigest, EffectFacts,
        EffectPlace, GrantBound, UndoFidelity,
    };
    use oneiron_authority::federation::{Scope, ScopeAxis, Sensitivity, SensitivityCeiling};

    /// A bound whose `digest` is main's body; every other name reads the bound itself.
    pub struct Bound<'a>(pub &'a GrantBound);

    impl std::ops::Deref for Bound<'_> {
        type Target = GrantBound;

        fn deref(&self) -> &GrantBound {
            self.0
        }
    }

    /// A composed effect's fields, read through its public accessors, whose `digest` is
    /// main's body.
    pub struct Effect<'a> {
        facts: &'a EffectFacts,
        disclosure_requirement: Option<Bound<'a>>,
        action_requirement: Option<Bound<'a>>,
        place: EffectPlace,
        erase: bool,
    }

    impl<'a> Effect<'a> {
        pub fn of(effect: &'a ComposedEffect) -> Self {
            Self {
                facts: effect.facts(),
                disclosure_requirement: effect.disclosure_requirement().map(Bound),
                action_requirement: effect.action_requirement().map(Bound),
                place: effect.place(),
                erase: effect.is_erase(),
            }
        }
    }

    /// The tags main wrote first.
    pub const TAGS: [&[u8]; 2] = [BOUND_DIGEST_DOMAIN, EFFECT_DIGEST_DOMAIN];

    // main 55e034509eb1: crates/oneiron-store/src/consent_bound.rs:11-12
    /// Domain-separated BLAKE3 label for a normalized bound digest.
    const BOUND_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.bound_digest.v2\0";

    // main 55e034509eb1: crates/oneiron-store/src/consent_bound.rs:757-758
    pub const SUBJECT_KIND_ACTOR: &str = "actor";
    pub const SUBJECT_KIND_AUDIENCE: &str = "audience";

    // main 55e034509eb1: crates/oneiron-store/src/consent_bound.rs:793-798
    /// Length-prefixed field hashing, so `["ab","c"]` and `["a","bc"]` never
    /// collide into the same digest.
    pub fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    // main 55e034509eb1: crates/oneiron-store/src/consent_bound.rs:532-571
    // Hash each normalized authorization axis without a fallible serializer.
    // Scope is persisted in standing-grant rows; this digest must be stable after
    // decode and must distinguish two scopes with the same selector marker.
    fn hash_scope_axis<T: Ord>(
        hasher: &mut blake3::Hasher,
        axis: &ScopeAxis<T>,
        bytes: impl Fn(&T) -> Vec<u8>,
    ) {
        match axis {
            ScopeAxis::Bottom => {
                hasher.update(&[0]);
            }
            ScopeAxis::All => {
                hasher.update(&[1]);
            }
            ScopeAxis::Some(values) => {
                hasher.update(&[2]);
                hasher.update(&(values.len() as u64).to_be_bytes());
                for value in values {
                    hash_field(hasher, &bytes(value));
                }
            }
        }
    }

    fn hash_scope(hasher: &mut blake3::Hasher, scope: &Scope) {
        hash_field(hasher, b"contact-scope-v1");
        hash_scope_axis(hasher, &scope.worlds, |id| id.0.as_bytes().to_vec());
        hash_scope_axis(hasher, &scope.bands, |band| vec![*band]);
        hash_scope_axis(hasher, &scope.audience, |id| id.0.as_bytes().to_vec());
        hash_scope_axis(hasher, &scope.verbs, |verb| verb.as_bytes().to_vec());
        let sensitivity = match scope.sensitivity {
            SensitivityCeiling::Bottom => 0,
            SensitivityCeiling::AtMost(Sensitivity::Public) => 1,
            SensitivityCeiling::AtMost(Sensitivity::Private) => 2,
            SensitivityCeiling::AtMost(Sensitivity::Sensitive) => 3,
            SensitivityCeiling::AtMost(Sensitivity::Restricted) => 4,
        };
        hasher.update(&[sensitivity]);
    }

    impl Bound<'_> {
        // main 55e034509eb1: crates/oneiron-store/src/consent_bound.rs:667-743
            /// Engine-computed digest over the normalized bound, used as the
            /// `diff_handle` of a standing-grant receipt.
            #[must_use]
            pub fn digest(&self) -> EffectDigest {
                let mut hasher = blake3::Hasher::new();
                hasher.update(BOUND_DIGEST_DOMAIN);
                hash_field(&mut hasher, self.domain().as_str().as_bytes());
                match &self.subject {
                    BoundSubject::Actor(actor) => {
                        hash_field(&mut hasher, SUBJECT_KIND_ACTOR.as_bytes());
                        hash_field(&mut hasher, actor.actor_ref.as_bytes());
                        match actor.actor_class.as_deref() {
                            None => {
                                hasher.update(&[0]);
                            }
                            Some(class) => {
                                hasher.update(&[1]);
                                hash_field(&mut hasher, class.as_bytes());
                            }
                        }
                    }
                    BoundSubject::Audience(audience) => {
                        hash_field(&mut hasher, SUBJECT_KIND_AUDIENCE.as_bytes());
                        hasher.update(&(audience.members.len() as u64).to_be_bytes());
                        for member in &audience.members {
                            hash_field(&mut hasher, member.as_bytes());
                        }
                    }
                }
                hash_field(&mut hasher, b"class");
                hash_field(&mut hasher, self.class.as_str().as_bytes());
                match &self.envelope {
                    BoundEnvelope::Disclosure(envelope) => {
                        hash_field(&mut hasher, b"envelope:disclosure");
                        hasher.update(&(envelope.selectors.len() as u64).to_be_bytes());
                        for selector in &envelope.selectors {
                            hash_field(&mut hasher, selector.as_bytes());
                        }
                        match &envelope.scope {
                            None => {
                                hasher.update(&[0]);
                            }
                            Some(scope) => {
                                hasher.update(&[1]);
                                hash_scope(&mut hasher, scope);
                            }
                        }
                    }
                    BoundEnvelope::Action(envelope) => {
                        hash_field(&mut hasher, b"envelope:action");
                        hasher.update(&(envelope.selectors.len() as u64).to_be_bytes());
                        for selector in &envelope.selectors {
                            hash_field(&mut hasher, selector.as_bytes());
                        }
                        match envelope.target.as_deref() {
                            None => {
                                hasher.update(&[0]);
                            }
                            Some(target) => {
                                hasher.update(&[1]);
                                hash_field(&mut hasher, target.as_bytes());
                            }
                        }
                        match envelope.budget {
                            None => {
                                hasher.update(&[0]);
                            }
                            Some(budget) => {
                                hasher.update(&[1]);
                                hasher.update(&budget.to_be_bytes());
                            }
                        }
                        hasher.update(&[u8::from(envelope.receipt_required)]);
                    }
                }
                EffectDigest::from_bytes(*hasher.finalize().as_bytes())
            }
    }

    // main 55e034509eb1: crates/oneiron/src/consent/effect.rs:8-9
    /// Domain-separated BLAKE3 label for [`EffectDigest`].
    const EFFECT_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.effect_digest.v1\0";

    // main 55e034509eb1: crates/oneiron/src/consent/support.rs:27-34
    pub(super) const fn undo_fidelity_byte(fidelity: UndoFidelity) -> u8 {
        match fidelity {
            UndoFidelity::Full => 0,
            UndoFidelity::Partial => 1,
            UndoFidelity::None => 2,
            UndoFidelity::Unknown => 3,
        }
    }

    impl Effect<'_> {
        // main 55e034509eb1: crates/oneiron/src/consent/effect.rs:388-428
            /// The engine-computed digest identifying this exact op.
            #[must_use]
            pub fn digest(&self) -> EffectDigest {
                let mut hasher = blake3::Hasher::new();
                hasher.update(EFFECT_DIGEST_DOMAIN);
                hash_field(&mut hasher, self.facts.operation_kind.as_bytes());
                hasher.update(&[
                    u8::from(self.facts.fires_hooks),
                    u8::from(self.facts.triggers_publish),
                    u8::from(self.facts.external_observers),
                    undo_fidelity_byte(self.facts.undo_fidelity),
                ]);
                hasher.update(&self.facts.blast_radius.to_be_bytes());
                hash_field(
                    &mut hasher,
                    self.facts
                        .catastrophe
                        .map(CatastropheClass::as_str)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                for requirement in [&self.disclosure_requirement, &self.action_requirement] {
                    match requirement {
                        Some(bound) => hash_field(&mut hasher, bound.digest().as_bytes()),
                        None => hash_field(&mut hasher, &[]),
                    }
                }
                // Appended only when set, so every digest minted before these facts
                // existed stays the digest of the same op.
                if self.place != EffectPlace::default() || self.erase {
                    hash_field(&mut hasher, b"place");
                    for id in [self.place.project, self.place.thread] {
                        hash_field(
                            &mut hasher,
                            id.as_ref().map_or(&[][..], |id| id.as_bytes().as_slice()),
                        );
                    }
                    hasher.update(&[u8::from(self.erase)]);
                }
                EffectDigest::from_bytes(*hasher.finalize().as_bytes())
            }
    }
}

fn id(seed: u8) -> Result<EntityId> {
    EntityId::from_bytes(std::array::from_fn(|at| seed ^ (at as u8).wrapping_mul(17)))
}

fn axis<T: Ord>(values: impl IntoIterator<Item = T>) -> ScopeAxis<T> {
    ScopeAxis::Some(values.into_iter().collect::<BTreeSet<T>>())
}

fn scopes() -> Result<Vec<Scope>> {
    let empty = Scope {
        worlds: ScopeAxis::Bottom,
        facets: ScopeAxis::Bottom,
        bands: ScopeAxis::Bottom,
        audience: ScopeAxis::Bottom,
        verbs: ScopeAxis::Bottom,
        sensitivity: SensitivityCeiling::Bottom,
    };
    Ok(vec![
        Scope::top(),
        empty.clone(),
        Scope {
            worlds: axis([ScopeId(id(1)?), ScopeId(id(2)?)]),
            facets: axis([ScopeId(id(3)?)]),
            bands: axis([0_u8, 3, u8::MAX]),
            audience: axis(Vec::<ScopeId>::new()),
            verbs: axis([String::new(), "read".to_owned(), "write".to_owned()]),
            sensitivity: SensitivityCeiling::AtMost(Sensitivity::Public),
        },
        Scope {
            worlds: ScopeAxis::All,
            audience: axis([ScopeId(id(4)?)]),
            verbs: axis(["\u{65e5}\u{672c}\u{0}".to_owned()]),
            sensitivity: SensitivityCeiling::AtMost(Sensitivity::Private),
            ..empty.clone()
        },
        Scope {
            bands: axis([7_u8]),
            facets: ScopeAxis::All,
            sensitivity: SensitivityCeiling::AtMost(Sensitivity::Sensitive),
            ..empty.clone()
        },
        Scope {
            verbs: ScopeAxis::All,
            sensitivity: SensitivityCeiling::AtMost(Sensitivity::Restricted),
            ..Scope::top()
        },
    ])
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn subjects() -> Vec<BoundSubject> {
    let actor = |actor_ref: &str, actor_class: Option<&str>| {
        BoundSubject::Actor(ActorBound {
            actor_ref: actor_ref.to_owned(),
            actor_class: actor_class.map(str::to_owned),
        })
    };
    let audience = |members: &[&str]| {
        BoundSubject::Audience(AudienceBound {
            members: strings(members),
        })
    };
    vec![
        actor("", None),
        actor("agent:alpha", None),
        actor("agent:alpha", Some("")),
        actor("\u{65e5}\u{672c}-\u{1f600}\u{0}\n", Some("worker")),
        audience(&[]),
        audience(&["alice"]),
        audience(&["zeta", "alpha", "alpha"]),
        audience(&["ab", "c"]),
        audience(&["a", "bc"]),
    ]
}

fn classes() -> Result<Vec<BoundClass>> {
    Ok(vec![
        BoundClass::Disclosure(DisclosureClass::new("contact")?),
        BoundClass::Disclosure(DisclosureClass::new("say \"hi\"\\\u{7f}")?),
        BoundClass::Action(ActionClass::new("send")?),
    ])
}

fn envelopes() -> Result<Vec<BoundEnvelope>> {
    let disclosure = |selectors: &[&str], scope: Option<Scope>| {
        BoundEnvelope::Disclosure(DisclosureEnvelope {
            selectors: strings(selectors),
            scope: scope.map(Box::new),
        })
    };
    let action =
        |selectors: &[&str], target: Option<&str>, budget: Option<u64>, receipt_required| {
            BoundEnvelope::Action(ActionEnvelope {
                selectors: strings(selectors),
                target: target.map(str::to_owned),
                budget,
                receipt_required,
            })
        };
    let mut envelopes = vec![
        disclosure(&[], None),
        disclosure(&["b", "a"], None),
        action(&[], None, None, false),
        action(&["x"], Some(""), Some(0), true),
        action(&["x", "y"], Some("target"), Some(u64::MAX), false),
        action(&["\u{0}"], None, Some(1), true),
    ];
    for scope in scopes()? {
        envelopes.push(disclosure(&["scope:clearance"], Some(scope)));
    }
    Ok(envelopes)
}

fn bounds() -> Result<Vec<GrantBound>> {
    let mut bounds = Vec::new();
    for subject in subjects() {
        for class in classes()? {
            for envelope in envelopes()? {
                bounds.push(GrantBound {
                    subject: subject.clone(),
                    class: class.clone(),
                    envelope,
                });
            }
        }
    }
    Ok(bounds)
}

/// Domain-consistent requirements: (disclosure, action).
fn requirements() -> Result<Vec<(Option<GrantBound>, Option<GrantBound>)>> {
    let disclosure = |members: &[&str], selectors: &[&str], scope: Option<Scope>| {
        Ok::<_, oneiron::Error>(GrantBound::disclosure(
            AudienceBound::new(strings(members))?,
            DisclosureClass::new("contact")?,
            match scope {
                Some(scope) => DisclosureEnvelope::from_scope(scope)?,
                None => DisclosureEnvelope::new(strings(selectors))?,
            },
        )?)
    };
    let action = |actor: &str, budget: Option<u64>| {
        let mut envelope = ActionEnvelope::new(strings(&["thread:1"]))?.with_target("room")?;
        if let Some(budget) = budget {
            envelope = envelope.with_budget(budget).with_receipt_required(true);
        }
        Ok::<_, oneiron::Error>(GrantBound::action(
            ActorBound::new(actor)?.with_actor_class("agent")?,
            ActionClass::new("send")?,
            envelope,
        )?)
    };
    Ok(vec![
        (None, None),
        (Some(disclosure(&["bob", "alice"], &["notes"], None)?), None),
        (None, Some(action("agent:alpha", None)?)),
        (
            Some(disclosure(&["carol"], &[], Some(Scope::top()))?),
            Some(action("agent:beta", Some(u64::MAX))?),
        ),
    ])
}

fn facts() -> Vec<EffectFacts> {
    let catastrophes = [
        None,
        Some(CatastropheClass::WidenOwnAuthority),
        Some(CatastropheClass::KeyRecovery),
        Some(CatastropheClass::VaultWideDestruction),
        Some(CatastropheClass::SecurityControlDisable),
        Some(CatastropheClass::MassSecretExport),
        Some(CatastropheClass::WorldPrivacyWiden),
        Some(CatastropheClass::ProtectedRefRewriteOrDelete),
    ];
    let undo = [
        UndoFidelity::Full,
        UndoFidelity::Partial,
        UndoFidelity::None,
        UndoFidelity::Unknown,
    ];
    let kinds = ["", "claim.put", "channel.send", "\u{65e5}\u{672c}\u{0}"];
    let blast = [0, 1, 100, u64::MAX];
    let mut facts = Vec::new();
    for (at, catastrophe) in catastrophes.into_iter().enumerate() {
        facts.push(EffectFacts {
            operation_kind: kinds[at % kinds.len()].to_owned(),
            fires_hooks: at & 1 == 1,
            triggers_publish: at & 2 == 2,
            external_observers: at & 4 == 4,
            undo_fidelity: undo[at % undo.len()],
            blast_radius: blast[at % blast.len()],
            catastrophe,
        });
    }
    facts.push(EffectFacts {
        operation_kind: "x".repeat(300),
        fires_hooks: true,
        triggers_publish: true,
        external_observers: true,
        undo_fidelity: UndoFidelity::Unknown,
        blast_radius: u64::MAX,
        catastrophe: None,
    });
    facts
}

fn places() -> Result<Vec<EffectPlace>> {
    Ok(vec![
        EffectPlace::default(),
        EffectPlace {
            project: Some(id(5)?),
            thread: None,
        },
        EffectPlace {
            project: None,
            thread: Some(id(6)?),
        },
        EffectPlace {
            project: Some(id(7)?),
            thread: Some(id(8)?),
        },
    ])
}

#[test]
fn consent_purposes_keep_the_base_tags() {
    let kept = [
        purposes::consent::BOUND_DIGEST,
        purposes::consent::EFFECT_DIGEST,
    ];
    for (purpose, tag) in kept.into_iter().zip(base::TAGS) {
        assert_eq!(purpose.tag().as_bytes(), tag);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
    }
}

#[test]
fn bound_digest_equals_the_base_body() -> Result<()> {
    let bounds = bounds()?;
    for bound in &bounds {
        assert_eq!(
            bound.digest().as_bytes(),
            base::Bound(bound).digest().as_bytes(),
            "{bound:?}"
        );
    }
    // 9 subjects x 3 classes x 12 envelopes.
    assert_eq!(bounds.len(), 324);
    Ok(())
}

#[test]
fn effect_digest_equals_the_base_body() -> Result<()> {
    let mut checked = 0;
    for effect_facts in facts() {
        for (disclosure, action) in requirements()? {
            for place in places()? {
                for erase in [false, true] {
                    let mut effect = ComposedEffect::new(effect_facts.clone()).in_place(place);
                    if erase {
                        effect = effect.as_erase();
                    }
                    if let Some(bound) = disclosure.clone() {
                        effect = effect.with_disclosure_requirement(bound)?;
                    }
                    if let Some(bound) = action.clone() {
                        effect = effect.with_action_requirement(bound)?;
                    }
                    assert_eq!(
                        effect.digest().as_bytes(),
                        base::Effect::of(&effect).digest().as_bytes(),
                        "{effect:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    // 9 fact sets x 4 requirement pairs x 4 places x 2 erase flags.
    assert_eq!(checked, 288);
    Ok(())
}
