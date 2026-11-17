//! Threshold fixtures of the agent_definition scans for `no_engine_scan_refuses_for_its_row_count`
//! (FIX LIBTEST-SCAN-CHECK-TABLE-UNSEEDED-SCANS).

use super::*;
use crate::ports::DocumentRowStore;

/// A minimal definition: 1-byte identity/desc/version, no lists, no profile,
/// forked from `forked_from`. Every byte family but the arm's target stays at
/// or under ROW, so only that family raises its check.
fn agent_def(agent_id: &str, forked_from: Option<EntityId>) -> crate::agent_def::AgentDefinition {
    crate::agent_def::AgentDefinition::new(
        agent_id,
        "d",
        "v",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        crate::agent_def::AgentScope::Base,
        crate::agent_def::AgentCeiling::Auto,
        forked_from,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
        crate::claim::ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from("agent-definition"),
        )]),
        None,
        true,
        None,
    )
}

pub(super) fn seed(vault: &Vault, scan: EngineScan) -> Option<(usize, Read<'_>)> {
    match scan {
        EngineScan::AgentDefinitionListEntries => {
            // Three skills: the put door counts 3 entries past ROW in the
            // skills list; the other five lists are empty and raise nothing.
            let at = id(0x98, 0);
            let mut def = agent_def("a", None);
            def.skills = (0..PAST)
                .map(|index| crate::skill::SkillDependency::new(format!("s{index}")))
                .collect();
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::agent_id_pin_for_put_in_txn(&vault.store, &txn, &at, &def)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AgentBirthSkillRows => {
            // Three SKILL rows (headered, undecodable): the birth scan counts
            // 3 past ROW; with no match the refs resolve to none and the bind
            // stays empty, so both reads take the same path.
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let row = id(0x99, index);
                        let record = crate::test_util::entity_record(
                            crate::registry::ENTITY_TYPE_SKILL,
                            crate::temporal::TimeRange { start: 1, end: 1 },
                            1,
                            1,
                            b"skill",
                        );
                        vault.store.entities.put(wtxn, row.as_bytes(), &record)?;
                        let key = Store::encode_type_key(crate::registry::ENTITY_TYPE_SKILL, &row);
                        vault.store.type_index.put(wtxn, &key, &[])?;
                    }
                    Ok(())
                })
                .expect("seed");
            let child = id(0x99, PAST);
            let mut def = agent_def("birth.skills", None);
            def.skills = (0..PAST)
                .map(|index| crate::skill::SkillDependency::new(format!("wanted-{index}")))
                .collect();
            Some((
                PAST,
                Box::new(move || {
                    vault.with_write_txn(|wtxn| {
                        crate::agent_def::bind_agent_birth_in_txn(
                            &vault.store,
                            wtxn,
                            &child,
                            &def,
                        )?;
                        Ok(PAST)
                    })
                }),
            ))
        }
        EngineScan::AgentBirthClaimOfRows => {
            // A stored parent plus three ClaimOf edges into it: the birth
            // scan of a fork counts 3 past ROW, scoped to the parent, so the
            // bind's check is the same on both reads.
            let parent = id(0x9A, PAST);
            let at = crate::temporal::TimeRange { start: 10, end: 10 };
            vault
                .put_agent_definition(&parent, &agent_def("birth.parent", None), at, 10)
                .expect("seed");
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key =
                            Store::encode_edge_key(&parent, EdgeKind::ClaimOf, &id(0x9A, index));
                        vault.store.edges_in.put(wtxn, &key, &edge_value())?;
                    }
                    Ok(())
                })
                .expect("seed");
            let child = id(0x9A, PAST + 1);
            let def = agent_def("birth.fork", Some(parent));
            Some((
                PAST,
                Box::new(move || {
                    vault.with_write_txn(|wtxn| {
                        crate::agent_def::bind_agent_birth_in_txn(
                            &vault.store,
                            wtxn,
                            &child,
                            &def,
                        )?;
                        Ok(PAST)
                    })
                }),
            ))
        }
        EngineScan::AgentDefinitionIdentityBytes => {
            // A 3-byte agent id: the put door counts 3 past ROW in agentId.
            let at = id(0x9B, 0);
            let def = agent_def("abc", None);
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::agent_id_pin_for_put_in_txn(&vault.store, &txn, &at, &def)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AgentDefinitionDescriptionBytes => {
            // A 3-byte desc: the put door counts 3 past ROW in desc.
            let at = id(0x9C, 0);
            let mut def = agent_def("a", None);
            def.desc = "abc".to_owned();
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::agent_id_pin_for_put_in_txn(&vault.store, &txn, &at, &def)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AgentDefinitionVersionBytes => {
            // A 3-byte version: the put door counts 3 past ROW in version.
            let at = id(0x9D, 0);
            let mut def = agent_def("a", None);
            def.version = "abc".to_owned();
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::agent_id_pin_for_put_in_txn(&vault.store, &txn, &at, &def)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AgentDefinitionInstructionBytes => {
            // 3-byte instructions: the put door counts 3 past ROW in them.
            let at = id(0x9E, 0);
            let mut def = agent_def("a", None);
            def.instructions = Some("abc".to_owned());
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::agent_id_pin_for_put_in_txn(&vault.store, &txn, &at, &def)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AgentDefinitionReferenceBytes => {
            // A 3-byte connector: the put door counts 3 past ROW in it.
            let at = id(0x9F, 0);
            let mut def = agent_def("a", None);
            def.connectors = vec!["abc".to_owned()];
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::agent_id_pin_for_put_in_txn(&vault.store, &txn, &at, &def)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AgentDefinitionVerbatimPinBytes => {
            // A 3-byte verbatim pin: the put door counts 3 past ROW in it.
            let at = id(0xA0, 0);
            let mut def = agent_def("a", None);
            def.memory_profile = Some(
                crate::agent_def::MemoryProfile::new(
                    1024,
                    crate::llm::ModelTierRef("cb".to_owned()),
                    crate::agent_def::CompactionOwnership::Engine,
                )
                .with_verbatim_pins(vec!["abc".to_owned()]),
            );
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::agent_id_pin_for_put_in_txn(&vault.store, &txn, &at, &def)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AgentBirthSourceBytes => {
            // A captured birth source: the carrier put counts its bytes past
            // ROW, and each read revalidates the same carrier bytes.
            let child = id(0xA1, 0);
            let at = crate::temporal::TimeRange { start: 10, end: 10 };
            vault
                .put_agent_definition(&child, &agent_def("birth.source", None), at, 10)
                .expect("seed");
            let asset = crate::agent_def::birth_source_id(&child).expect("asset id");
            let raw = vault
                .get_raw(&asset)
                .expect("carrier")
                .expect("carrier row");
            let body = raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec();
            let served = body.len();
            Some((
                served,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::agent_def::validate_birth_source_put(
                        &vault.store,
                        &txn,
                        &asset,
                        crate::registry::ENTITY_TYPE_ASSET,
                        &body,
                    )?;
                    Ok(body.len())
                }),
            ))
        }
        EngineScan::NoteDocumentBytes => {
            // A NOTE head snapshot with a 3-byte body: the load counts 3
            // past ROW and serves the body.
            let note = id(0xA2, 0);
            let doc = loro::LoroDoc::new();
            doc.get_map("meta")
                .insert("id", note.to_hex())
                .expect("identity");
            doc.get_text("body").insert(0, "abc").expect("body");
            doc.commit();
            let snapshot = doc.export(loro::ExportMode::Snapshot).expect("snapshot");
            vault
                .with_write_txn(|wtxn| {
                    vault.store.port_document_snapshot_put(
                        wtxn,
                        crate::ports::DocumentSlot::of(note),
                        &snapshot,
                    )
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let doc = crate::note::storage::load_for_erasure(vault, &txn, note)?;
                    Ok(doc.get_text("body").len_utf8())
                }),
            ))
        }
        EngineScan::NoteDocumentPinRows => {
            // A NOTE head snapshot with 3 pins: the load counts 3 past ROW.
            let note = id(0xA3, 0);
            let doc = loro::LoroDoc::new();
            doc.get_map("meta")
                .insert("id", note.to_hex())
                .expect("identity");
            doc.get_text("body").insert(0, "a").expect("body");
            let pins = doc
                .get_map("meta")
                .insert_container("pins", loro::LoroMap::new())
                .expect("pins");
            for index in 0..PAST {
                pins.insert(&format!("p{index}"), "x".to_owned())
                    .expect("pin");
            }
            doc.commit();
            let snapshot = doc.export(loro::ExportMode::Snapshot).expect("snapshot");
            vault
                .with_write_txn(|wtxn| {
                    vault.store.port_document_snapshot_put(
                        wtxn,
                        crate::ports::DocumentSlot::of(note),
                        &snapshot,
                    )
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let doc = crate::note::storage::load_for_erasure(vault, &txn, note)?;
                    Ok(match doc.get_map("meta").get("pins") {
                        Some(loro::ValueOrContainer::Container(loro::Container::Map(pins))) => {
                            pins.len()
                        }
                        _ => 0,
                    })
                }),
            ))
        }
        EngineScan::NoteDocumentAuthorshipRows => {
            // A NOTE head snapshot with 3 authorship entries: the load counts
            // 3 past ROW.
            let note = id(0xA4, 0);
            let doc = loro::LoroDoc::new();
            doc.get_map("meta")
                .insert("id", note.to_hex())
                .expect("identity");
            doc.get_text("body").insert(0, "a").expect("body");
            let authorship = doc.get_map("authorship");
            for index in 0..PAST {
                authorship
                    .insert(&format!("a{index}"), "x".to_owned())
                    .expect("authorship");
            }
            doc.commit();
            let snapshot = doc.export(loro::ExportMode::Snapshot).expect("snapshot");
            vault
                .with_write_txn(|wtxn| {
                    vault.store.port_document_snapshot_put(
                        wtxn,
                        crate::ports::DocumentSlot::of(note),
                        &snapshot,
                    )
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let doc = crate::note::storage::load_for_erasure(vault, &txn, note)?;
                    Ok(doc.get_map("authorship").len())
                }),
            ))
        }
        other => unreachable!("{} is seeded in another module", other.code()),
    }
}
