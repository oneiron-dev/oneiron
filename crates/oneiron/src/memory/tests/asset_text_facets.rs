//! Facet rule C at the public Memory read: a generated image's ASSET_TEXT is
//! born under the image's facet, so an agent whose proof is limited to that
//! facet resolves the image to its caption.

use super::*;
use crate::federation::{ScopeAxis, ScopeId};
use crate::llm::CallPurpose;
use crate::llm::image::{ImageBytes, ImageResponse};
use crate::memory::{AssetConsumer, ServedAssetForm};
use crate::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_FACET};
use std::collections::BTreeSet;

const CAPTION: &str = "a heron over a frozen canal";

/// Rule C on `resolve_asset`: the owner lands a generated image while facet
/// F is the vault default, and an agent whose verified proof reads F, ASSET
/// and ASSET_TEXT rows resolves it, as a text-only consumer, to its caption.
/// On main the caption was born under no facet, so the agent's read found no
/// form and refused it as `NOT_FOUND`.
#[test]
fn a_facet_limited_agent_resolves_a_generated_image_to_its_caption() {
    let (_dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facet = EntityId::from_bytes([0xF1; 16]).expect("facet id");
    vault
        .put_entity(&facet, ENTITY_TYPE_FACET, test_time(1), 1, b"facet")
        .expect("put facet");
    vault
        .set_default_facet(facet, crate::WriteActor::new(owner, EdgeActorClass::Human))
        .expect("default facet");
    let landed = facade_for(&vault, owner)
        .land_generated_image(
            &ImageResponse {
                image: ImageBytes {
                    bytes: b"\x89PNG\r\n\x1a\nfaceted pixels".to_vec(),
                    media_type: "image/png".into(),
                },
                model: crate::llm::ModelId::new("fake/image-1@1").expect("model id"),
                metadata: std::collections::BTreeMap::new(),
            },
            CAPTION,
            10,
        )
        .expect("land the generated image");

    let agent = put_person(&vault, 0xA7);
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"asset text facets").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(agent.as_bytes()).as_bytes();
    claims.holder_ref = agent.to_hex();
    claims.actor_class = Some("agent".into());
    claims.scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(facet)]));
    claims.scope.bands = ScopeAxis::Some([ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT].into());
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let signature = issuer.binding_proof(&slip, b"asset-read").unwrap();
    let proof = vault
        .verify_capability_slip(&issuer.public_key(), &slip, b"asset-read", &signature)
        .unwrap();

    let resolved = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof)
        .resolve_asset(
            &landed.asset_ref,
            &AssetConsumer::text_only(CallPurpose::AnswerGen),
            None,
        )
        .expect("the agent resolves the image")
        .value;
    assert_eq!(resolved.form, ServedAssetForm::AssetText);
    assert_eq!(resolved.text.as_deref(), Some(CAPTION));
    assert_eq!(resolved.asset_text_ref, Some(landed.asset_text_ref));
    assert!(resolved.image.is_none());
}
