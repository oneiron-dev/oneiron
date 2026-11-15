//! The recovery preset routes: read the vault key's recovery preset, and set
//! it, with the kit for a switch to Nobody but me.

use super::*;

/// `GET /v1/owner/vault-key/recovery-preset`: the owner's recovery preset.
pub(super) async fn recovery_preset(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<RecoveryPresetView> {
    owner(&auth, &server)?;
    let view = blocking(move || {
        Ok(RecoveryPresetView {
            preset: server.vault().recovery_preset()?,
        })
    })
    .await?;
    Ok(Json(view))
}

/// The recovery kit as the caller gave it. No `Debug`: it carries the kit.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecoveryKitInput {
    /// The recovery kit's pieces as recovery codes.
    pieces: Vec<String>,
    /// The kit passphrase, where one point is the passphrase.
    #[serde(default)]
    passphrase: Option<String>,
}

/// No `Debug`: it can carry the kit.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecoveryPresetRequest {
    /// `standard` or `nobody_but_me`; `nobody_but_me_any_two` is refused
    /// here, as it is turned on with its kit.
    preset: RecoveryPreset,
    /// Entering `nobody_but_me` while a generation is live needs the recovery
    /// kit that replaces the key the box could release. Omitted clients still
    /// parse; without it the switch is refused while live.
    #[serde(default)]
    kit: Option<RecoveryKitInput>,
}

/// `PUT /v1/owner/vault-key/recovery-preset`: sets the owner's recovery
/// preset, the owner rechecked in the write. Entering `nobody_but_me` needs
/// the vault key held, an owner-held key custody and this install's device
/// wrap, which stays; its answer carries the printed sheet's code, once.
/// Entering while a generation is live needs the recovery kit in `kit`, which
/// replaces the key the box could release; without it the switch is refused.
pub(super) async fn set_recovery_preset(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RecoveryPresetRequest>,
) -> OwnerReply<RecoveryPresetSet> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let set = blocking(move || -> OwnerResult<RecoveryPresetSet> {
        let vault: &oneiron::Vault = match request.preset {
            RecoveryPreset::NobodyButMe | RecoveryPreset::NobodyButMeAnyTwo => {
                held(server.vault())?
            }
            RecoveryPreset::Standard => server.vault().as_ref(),
        };
        // The answer is the sheet's only hand-over: the engine enters the
        // preset only while this install's device wrap stays, so a lost
        // answer locks no one out (review of #7766, round 2).
        let change = match request.kit {
            Some(kit) => {
                let kit = Kit::parse(kit.pieces, kit.passphrase)?;
                let pieces = kit.pieces();
                let authority = ActAuthority::Owner(owner, surface);
                vault.set_recovery_preset_answered_with_kit_as(
                    &authority,
                    request.preset,
                    &pieces,
                    kit.passphrase.as_ref(),
                    &NoRecoveryBox,
                )?
            }
            None => {
                vault.set_recovery_preset_answered_as(&owner, request.preset, &NoRecoveryBox)?
            }
        };
        let (mut set, sheet) = RecoveryPresetSet::of(&vault.vault_key_vault_id(), change);
        set.sheet_code = sheet.map(|sheet| sheet.code().as_str().to_owned());
        Ok(set)
    })
    .await?;
    Ok(Json(set))
}

/// The OpenAPI schema of `PUT /v1/owner/vault-key/recovery-preset`'s body:
/// [`RecoveryPresetRequest`].
pub(crate) fn set_recovery_preset_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RecoveryPresetRequest>()
}

/// The OpenAPI schema of `PUT /v1/owner/vault-key/recovery-preset`'s answer:
/// [`RecoveryPresetSet`].
pub(crate) fn recovery_preset_set_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RecoveryPresetSet>()
}
