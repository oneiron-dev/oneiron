//! Witness messages: ceilings, envelope binding, and replicated refusal.

use super::*;

fn witness_envelope() -> WitnessMessageEnvelope<'static> {
    WitnessMessageEnvelope {
        author: WITNESS_AUTHOR_COMPANION,
        message_type: "dialogue",
        content: "the answer",
        metadata: Some(Value::Map(vec![(
            Value::from("client"),
            Value::from("cli"),
        )])),
        is_visible: true,
        order: 1,
    }
}

/// Class-wide claim ceilings do not mute transcript recording. Only an exact
/// actor-ref row clamps an ordinary witness MESSAGE, and class-wide rows are not
/// folded into that exact-row verdict. The elevated `system` bucket still needs
/// exact actor-bound Auto authority.
#[test]
fn witness_message_ignores_class_wide_ceilings_but_honors_actor_bound_rows() -> Result<()> {
    let actor_id = test_id(0x20);
    let actor_ref = actor_id.to_hex();
    let actor = WriteActor::new(actor_id, EdgeActorClass::Agent);

    for (label, rows, should_allow) in [
        (
            "class proposed only",
            vec![actor_ceiling_row("agent", "proposed")],
            true,
        ),
        (
            "class proposed plus exact auto",
            vec![
                actor_ceiling_row("agent", "proposed"),
                actor_ceiling_row_for_ref("agent", &actor_ref, "auto"),
            ],
            true,
        ),
        (
            "class auto plus exact proposed",
            vec![
                actor_ceiling_row("agent", "auto"),
                actor_ceiling_row_for_ref("agent", &actor_ref, "proposed"),
            ],
            false,
        ),
    ] {
        let (_tmp, vault) = temp_vault();
        let mut manifest = default_policy_manifest();
        replace_actor_ceilings(&mut manifest, rows);
        put_policy_manifest_bytes(&vault, default_policy_manifest_id()?, &manifest)?;
        let rtxn = vault.store.env.read_txn()?;
        let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
        let envelope = witness_envelope();
        let body = envelope.encode_body()?;
        let result =
            check_witness_message_ceiling(&vault.store, &rtxn, actor, &envelope, &body, &policy);
        if should_allow {
            result.unwrap_or_else(|error| panic!("{label} must allow ordinary recording: {error}"));
        } else {
            let error = result.expect_err("exact proposed row must clamp ordinary recording");
            assert_eq!(
                error.gate_denial().expect("typed denial").reason_codes(),
                &[GateDenialReason::PendingActorCeiling],
                "{label}",
            );
        }
    }

    let (_tmp, vault) = temp_vault();
    let mut manifest = default_policy_manifest();
    replace_actor_ceilings(&mut manifest, vec![actor_ceiling_row("agent", "auto")]);
    put_policy_manifest_bytes(&vault, default_policy_manifest_id()?, &manifest)?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
    let system = WitnessMessageEnvelope {
        author: WITNESS_AUTHOR_SYSTEM,
        ..witness_envelope()
    };
    let body = system.encode_body()?;
    let error = check_witness_message_ceiling(&vault.store, &rtxn, actor, &system, &body, &policy)
        .expect_err("class-wide auto is not authority for system authorship");
    assert_eq!(
        error.gate_denial().expect("typed denial").reason_codes(),
        &[GateDenialReason::DenyWitnessMessageAuthorNotAuthorized],
    );
    Ok(())
}

/// A malformed manifest stays fail-closed even when its decoded rows happen to
/// contain an exact actor-bound auto ceiling. The system-author floor must not
/// treat partially decoded policy data as authority.
#[test]
fn witness_message_system_authority_rejects_fail_closed_policy_with_auto_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor_id = test_id(0x21);
    let actor = WriteActor::new(actor_id, EdgeActorClass::Agent);
    let mut manifest = default_policy_manifest();
    replace_actor_ceilings(
        &mut manifest,
        vec![actor_ceiling_row_for_ref(
            "agent",
            &actor_id.to_hex(),
            "auto",
        )],
    );
    rewrite_policy_manifest_entries(&mut manifest, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_DEFAULTS_KEY) {
                let Value::Map(defaults) = value else {
                    unreachable!("defaults are a map");
                };
                defaults.push((Value::from("future_axis"), Value::from("permit")));
            }
        }
    });
    put_policy_manifest_bytes(&vault, default_policy_manifest_id()?, &manifest)?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(policy.is_fail_closed());
    let envelope = WitnessMessageEnvelope {
        author: WITNESS_AUTHOR_SYSTEM,
        ..witness_envelope()
    };
    let body = envelope.encode_body()?;
    let error =
        check_witness_message_ceiling(&vault.store, &rtxn, actor, &envelope, &body, &policy)
            .expect_err("fail-closed policy cannot authorize system authorship");
    assert_eq!(
        error.gate_denial().expect("typed denial").reason_codes(),
        &[GateDenialReason::DenyWitnessMessageAuthorNotAuthorized],
    );
    Ok(())
}

/// Metadata is bounded by bytes as well as shape. A single value is capped,
/// multibyte UTF-8 counts by encoded bytes, and individually legal values may
/// not combine into an oversized canonical metadata map.
#[test]
fn witness_message_metadata_enforces_string_and_total_byte_ceilings() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
    let actor = WriteActor::new(test_id(0x2F), EdgeActorClass::Human);
    let authorize = |metadata: Value| {
        let envelope = WitnessMessageEnvelope {
            metadata: Some(metadata),
            ..witness_envelope()
        };
        let body = envelope.encode_body().expect("metadata encodes");
        check_witness_message_ceiling(&vault.store, &rtxn, actor, &envelope, &body, &policy)
            .map(|_| ())
    };

    authorize(Value::Map(vec![(
        Value::from("value"),
        Value::from("a".repeat(16 * 1024)),
    )]))
    .expect("one string exactly at the byte ceiling is allowed");
    authorize(Value::Map(vec![(
        Value::from("value"),
        Value::from("é".repeat(8 * 1024)),
    )]))
    .expect("multibyte text exactly at the UTF-8 byte ceiling is allowed");

    for (label, metadata) in [
        (
            "one byte past the string ceiling",
            Value::Map(vec![(
                Value::from("value"),
                Value::from("a".repeat(16 * 1024 + 1)),
            )]),
        ),
        (
            "one multibyte scalar past the string ceiling",
            Value::Map(vec![(
                Value::from("value"),
                Value::from("é".repeat(8 * 1024 + 1)),
            )]),
        ),
        (
            "aggregate metadata past the encoded ceiling",
            Value::Map(
                (0..4)
                    .map(|index| {
                        (
                            Value::from(format!("value_{index}")),
                            Value::from("a".repeat(16 * 1024)),
                        )
                    })
                    .collect(),
            ),
        ),
    ] {
        let error = authorize(metadata)
            .err()
            .unwrap_or_else(|| panic!("{label} must be refused"));
        assert_eq!(
            error.gate_denial().expect("typed denial").reason_codes(),
            &[GateDenialReason::DenyWitnessMessageMalformedEnvelope],
            "{label}",
        );
    }
    Ok(())
}

/// Invariant 3: EVERY envelope axis feeds the binding, so no axis can move
/// between the authorization and the write without the binding moving with it.
/// Content-only or author-only hashing would collapse most of these to one
/// value; each variant here changes exactly one axis.
#[test]
fn witness_message_binding_moves_with_every_envelope_axis() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
    let actor = WriteActor::new(test_id(0x21), EdgeActorClass::Human);
    let base = witness_envelope();

    let variants = vec![
        (
            "author",
            WitnessMessageEnvelope {
                author: WITNESS_AUTHOR_USER,
                ..base.clone()
            },
        ),
        (
            "message_type",
            WitnessMessageEnvelope {
                message_type: "executor.speak",
                ..base.clone()
            },
        ),
        (
            "content",
            WitnessMessageEnvelope {
                content: "the answer.",
                ..base.clone()
            },
        ),
        (
            "metadata value",
            WitnessMessageEnvelope {
                metadata: Some(Value::Map(vec![(
                    Value::from("client"),
                    Value::from("gui"),
                )])),
                ..base.clone()
            },
        ),
        (
            "metadata key",
            WitnessMessageEnvelope {
                metadata: Some(Value::Map(vec![(
                    Value::from("surface"),
                    Value::from("cli"),
                )])),
                ..base.clone()
            },
        ),
        (
            "metadata nested one level down",
            WitnessMessageEnvelope {
                metadata: Some(Value::Map(vec![(
                    Value::from("client"),
                    Value::Map(vec![(Value::from("build"), Value::from("cli"))]),
                )])),
                ..base.clone()
            },
        ),
        (
            "metadata absent",
            WitnessMessageEnvelope {
                metadata: None,
                ..base.clone()
            },
        ),
        (
            "is_visible",
            WitnessMessageEnvelope {
                is_visible: false,
                ..base.clone()
            },
        ),
        (
            "order",
            WitnessMessageEnvelope {
                order: 2,
                ..base.clone()
            },
        ),
    ];

    let authorize = |envelope: &WitnessMessageEnvelope<'_>, actor| -> Result<[u8; 32]> {
        let body = envelope.encode_body()?;
        Ok(
            check_witness_message_ceiling(&vault.store, &rtxn, actor, envelope, &body, &policy)?
                .binding(),
        )
    };

    let mut seen = vec![authorize(&base, actor)?];
    for (label, variant) in variants {
        let binding = authorize(&variant, actor)?;
        assert!(
            !seen.contains(&binding),
            "changing {label} left the binding unmoved"
        );
        seen.push(binding);
    }

    // The ACTOR is bound too: the same envelope presented by another writer is
    // a different authorization, not a reusable one.
    let other_actor = WriteActor::new(test_id(0x22), EdgeActorClass::Human);
    let rebound = authorize(&base, other_actor)?;
    assert!(
        !seen.contains(&rebound),
        "the binding must name the actor that presented the envelope"
    );
    Ok(())
}

/// Invariant 1: the pre-write check and the final write bind the SAME immutable
/// values. The door re-encodes the axes it authorized and refuses bytes that
/// are not that encoding, so a caller cannot have the door approve one envelope
/// and stage another.
#[test]
fn witness_message_door_refuses_staged_bytes_that_are_not_the_authorized_envelope() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
    let actor = WriteActor::new(test_id(0x23), EdgeActorClass::Human);
    let declared = witness_envelope();
    let staged = WitnessMessageEnvelope {
        content: "a completely different answer",
        is_visible: false,
        ..declared.clone()
    };

    let err = check_witness_message_ceiling(
        &vault.store,
        &rtxn,
        actor,
        &declared,
        &staged.encode_body()?,
        &policy,
    )
    .expect_err("staged bytes that are not the authorized envelope are refused");
    assert_eq!(err.kind(), ErrorKind::GateWriteRejected);
    assert_eq!(
        err.gate_denial().expect("typed denial").reason_codes(),
        &[GateDenialReason::DenyWitnessMessageMalformedEnvelope]
    );

    // The door's own bytes are what a write may consume, and they are the
    // canonical encoding of the axes it authorized.
    let body = declared.encode_body()?;
    let authorized =
        check_witness_message_ceiling(&vault.store, &rtxn, actor, &declared, &body, &policy)?;
    assert_eq!(authorized.body(), body.as_slice());
    Ok(())
}

/// A vault with NO policy manifest loaded keeps the fail-closed author floor:
/// an absent manifest is not consent for an engine-voiced `system` row, even
/// when the actor is a store-verified MACHINE/system identity.
#[test]
fn witness_message_author_floor_holds_without_a_policy_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let machine = test_id(0x24);
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        test_time(1),
        1,
        b"engine machine",
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(
        !policy.enforces_write_gate(),
        "the fixture vault carries no manifest"
    );

    let system_row = WitnessMessageEnvelope {
        author: WITNESS_AUTHOR_SYSTEM,
        ..witness_envelope()
    };
    let body = system_row.encode_body()?;

    for actor in [
        WriteActor::new(test_id(0x25), EdgeActorClass::Human),
        WriteActor::new(machine, EdgeActorClass::System),
    ] {
        let err =
            check_witness_message_ceiling(&vault.store, &rtxn, actor, &system_row, &body, &policy)
                .expect_err("no manifest or actor-bound row is consent");
        assert_eq!(
            err.gate_denial().expect("typed denial").reason_codes(),
            &[GateDenialReason::DenyWitnessMessageAuthorNotAuthorized]
        );
    }
    Ok(())
}

/// The metric class is its own label, so a witness refusal is not filed under
/// some other family's counter.
#[test]
fn witness_message_refusals_meter_under_their_own_reason_class() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &rtxn)?;
    let before = vault.diagnostics().gate.snapshot();

    let malformed = WitnessMessageEnvelope {
        message_type: "not a token",
        ..witness_envelope()
    };
    let body = malformed.encode_body()?;
    check_witness_message_ceiling(
        &vault.store,
        &rtxn,
        WriteActor::new(test_id(0x26), EdgeActorClass::Human),
        &malformed,
        &body,
        &policy,
    )
    .expect_err("an out-of-shape message type is refused");

    let after = vault.diagnostics().gate.snapshot();
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Deny,
        GateMetricReasonClass::WitnessMessageCeiling,
        1,
    );
    Ok(())
}

/// ONE-1686 (RT-04): the REPLICATED MESSAGE door fails closed for EVERY author
/// bucket — and closing it does not wedge the window.
///
/// The local witness ceiling is an ACTOR question, and the sync replay door has
/// no actor to ask it about: `WriteEnvelope` (the type that carries
/// `WriteActor` provenance into a write) appears nowhere in `crate::sync`, the
/// window key is a calendar month, the CRDT map key is the entity id, and the
/// six-axis envelope carries no signer. The kinds that DO admit remote rows
/// carry their proof INSIDE the body (an AUTHORITY_LOG entry names its signer;
/// a REDACTION_AUDIT receipt carries an attestation bound to a mirrored lease);
/// a MESSAGE has no such half, so there is nothing to bind remote authorship
/// to and admitting it would make sync a second, weaker MESSAGE authorization.
///
/// Four hostile rows arrive in one window — bytes that are not an envelope at
/// all, a forged `user` row, a forged `companion` row, and a row in the
/// engine's own unattributed `system` voice. All four are quarantined with the
/// typed reason and none leaves a body behind, while an ordinary TURN in the
/// SAME window still converges: this narrows one entity kind's remote door, not
/// sync in general.
#[cfg(feature = "sync")]
#[test]
fn forward_rematerialize_refuses_every_replicated_witness_message() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let window_key = WindowKey::new("2026-04");
    let doc = create_window_doc("local", &window_key);
    let entities = doc.get_map("entities");
    let at = TimeRange { start: 1, end: 1 };

    let insert = |id: &EntityId, entity_type: u8, body: &[u8]| {
        map_insert_bytes(
            &entities,
            &id.to_hex(),
            &entity_record(entity_type, at, 1, body),
        )
        .expect("insert replicated row");
    };

    // Not the canonical envelope at all.
    let malformed = test_id(0xB1);
    insert(
        &malformed,
        crate::registry::ENTITY_TYPE_MESSAGE,
        b"not an envelope",
    );

    // Well-formed transcript rows, which is exactly the point: the door cannot
    // tell an honest remote row from a forged one, because nothing here binds
    // either to an actor this vault verified.
    let forged_user = test_id(0xB2);
    insert(
        &forged_user,
        crate::registry::ENTITY_TYPE_MESSAGE,
        &canonical_witness_message_body_for_test("user", "dialogue", "i said this", true, 0)?,
    );
    let forged_companion = test_id(0xB3);
    insert(
        &forged_companion,
        crate::registry::ENTITY_TYPE_MESSAGE,
        &canonical_witness_message_body_for_test("companion", "dialogue", "and i this", true, 1)?,
    );
    // The engine's OWN voice: no `AuthoredBy` edge, so downstream it reads as
    // the vault speaking. Locally this needs an owner-authored, actor-bound
    // `auto` ceiling; no replicated envelope can present one.
    let forged_system = test_id(0xB4);
    insert(
        &forged_system,
        crate::registry::ENTITY_TYPE_MESSAGE,
        &canonical_witness_message_body_for_test("system", "tool_result", "ok", false, 2)?,
    );

    // An unrelated kind in the SAME window. One refused transcript row must not
    // cost this its convergence.
    let turn = test_id(0xB5);
    insert(&turn, crate::registry::ENTITY_TYPE_TURN, b"turn");
    doc.commit();

    let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    for refused in [malformed, forged_user, forged_companion, forged_system] {
        assert!(
            vault.get_raw(&refused)?.is_none(),
            "a refused replicated MESSAGE must leave no body behind: {}",
            refused.to_hex()
        );
    }
    assert!(
        vault.get_raw(&turn)?.is_some(),
        "an unrelated entity kind must still converge in the same window"
    );
    assert_eq!(materialized, 1, "only the TURN may materialize");

    let records = quarantined_records(&vault)?;
    let refusals = records
        .iter()
        .filter(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "InvalidWitnessMessageBody"
        })
        .count();
    assert_eq!(
        refusals, 4,
        "every refused MESSAGE is quarantined as a remote-op rejection, got {records:?}"
    );
    Ok(())
}

/// ONE-1686 (RT-04): a refused replicated MESSAGE rolls its whole batch back.
///
/// Observer B applies a replay batch as ONE transaction, so the refusal must
/// abort the batch rather than land the rows that happened to precede it —
/// otherwise a forged transcript row would still cost the window a partial
/// write. The sibling TURN here is a valid replicated put that would otherwise
/// have committed.
#[cfg(feature = "sync")]
#[test]
fn a_refused_replicated_witness_message_rolls_its_batch_back() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let turn = test_id(0xB6);
    let forged = test_id(0xB7);
    let at = TimeRange { start: 1, end: 1 };
    let body = canonical_witness_message_body_for_test("user", "dialogue", "forged", true, 0)?;

    let err = vault
        .batch()
        .put_replicated(&turn, crate::registry::ENTITY_TYPE_TURN, at, 1, b"turn")
        .put_replicated(&forged, crate::registry::ENTITY_TYPE_MESSAGE, at, 1, &body)
        .commit()
        .expect_err("a replicated MESSAGE has no local actor binding and is refused");
    assert_eq!(err.kind(), ErrorKind::InvalidWitnessMessageBody);
    assert!(
        crate::sync::quarantine::remote_rejection_reason(&err).is_some(),
        "the refusal must classify as a remote-op rejection so replay quarantines and continues"
    );
    assert!(vault.get_raw(&forged)?.is_none());
    assert!(
        vault.get_raw(&turn)?.is_none(),
        "the sibling op in the aborted batch must not survive the refusal"
    );
    Ok(())
}

/// ONE-1686 (RT-04): the LOCAL road is unchanged by the replicated closure.
///
/// The same canonical bytes the replicated door refuses are exactly what the
/// witness door writes, so this pins that the closure is about the ROAD (no
/// actor to authorize against) and not about the envelope: a locally witnessed
/// row still lands, and a raw local put of non-envelope bytes still fails on
/// the envelope floor rather than on the replicated rule.
#[test]
fn the_replicated_closure_leaves_the_local_message_road_intact() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0xB8);
    let conversation = test_id(0xB9);
    let message = test_id(0xBA);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"actor")?;

    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![crate::memory::WitnessMessage {
                id: Some(message.to_hex()),
                author: crate::memory::WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "a locally witnessed row".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 2,
        })
        .expect("the local witness door still writes MESSAGE rows");
    assert!(vault.get_raw(&message)?.is_some());

    let raw = test_id(0xBB);
    let err = vault
        .put_entity(
            &raw,
            crate::registry::ENTITY_TYPE_MESSAGE,
            test_time(1),
            1,
            b"not an envelope",
        )
        .expect_err("the public raw MESSAGE door stays closed");
    assert_eq!(err.kind(), ErrorKind::InvalidWitnessMessageBody);
    assert!(vault.get_raw(&raw)?.is_none());
    Ok(())
}

/// The shared materialization chokepoint treats a MESSAGE id as immutable.
/// Byte-identical replay is accepted, but a different canonical envelope at
/// the same id is refused and cannot replace the winner.
#[test]
fn witness_message_id_refuses_a_divergent_canonical_reput() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xBC);
    let first = canonical_witness_message_body_for_test(
        WITNESS_AUTHOR_COMPANION,
        "executor.speak",
        "winner",
        true,
        3,
    )?;
    let divergent = canonical_witness_message_body_for_test(
        WITNESS_AUTHOR_COMPANION,
        "executor.speak",
        "loser",
        true,
        3,
    )?;

    vault
        .batch()
        .put_canonical_message_for_test(&id, test_time(1), 1, &first)
        .commit()?;
    vault
        .batch()
        .put_canonical_message_for_test(&id, test_time(1), 1, &first)
        .commit()
        .expect("byte-identical MESSAGE retry is idempotent");
    let before = vault.get_raw(&id)?.expect("winning MESSAGE exists");

    let error = vault
        .batch()
        .put_canonical_message_for_test(&id, test_time(2), 2, &divergent)
        .commit()
        .expect_err("same-id divergent canonical body is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidWitnessMessageBody);
    assert_eq!(vault.get_raw(&id)?.as_deref(), Some(before.as_slice()));
    Ok(())
}
