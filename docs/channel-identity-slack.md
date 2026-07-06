# Slack Channel Identity Adapter

ONE-1512 implements Slack as an OF-347 `shared_presence` channel:

- one Oneiron Slack app is minted from a manifest with `apps.manifest.create`
- that one app can be installed into many Slack workspaces
- each Oneiron agent is represented as a named persona inside the app
- inbound Events API payloads are normalized through CID-6 with both the workspace stamp and the resolved ChannelIdentity

## Manifest Flow

Hosts build the manifest payload with `SlackSharedPresenceAdapter::apps_manifest_create_payload()`.
Slack's `apps.manifest.create` method expects the `manifest` argument to be a JSON-encoded string,
so the returned request body has this shape:

```json
{
  "manifest": "{\"display_information\":{\"name\":\"Oneiron\"},\"features\":{\"bot_user\":{\"display_name\":\"Oneiron\",\"always_online\":false}},\"oauth_config\":{\"redirect_urls\":[\"https://example.com/slack/oauth/callback\"],\"scopes\":{\"bot\":[\"app_mentions:read\",\"channels:history\",\"chat:write\",\"chat:write.customize\",\"commands\",\"im:history\",\"im:write\"]}},\"settings\":{\"event_subscriptions\":{\"request_url\":\"https://example.com/slack/events\",\"bot_events\":[\"app_mention\",\"message.im\"]},\"interactivity\":{\"is_enabled\":true,\"request_url\":\"https://example.com/slack/events\"},\"org_deploy_enabled\":false,\"socket_mode_enabled\":false,\"token_rotation_enabled\":true}}"
}
```

The app token used to call Slack stays host-side. Do not store Slack tokens in the vault.

## Workspace Install

After the app exists, each Slack workspace follows normal OAuth install using the manifest scopes. The adapter does not model a marketplace listing; distribution review is outside CID-8.

For each workspace/persona pair, create a `ChannelIdentity` with:

- `channel = "slack"`
- `shape = shared_presence`
- `binding = agent`
- `address_or_handle = slack:workspace:<TEAM_ID>:persona:<persona_handle>`

Use `SlackSharedPresenceAdapter::requested_identity(agent_ref, team_id, persona_handle, requested_at)`
for non-Enterprise workspaces. The adapter normalizes the persona handle and produces the same
canonical key used by inbound routing and outbound metadata.

Enterprise Grid workspaces use:

```text
slack:enterprise:<ENTERPRISE_ID>:workspace:<TEAM_ID>:persona:<persona_handle>
```

Use `SlackSharedPresenceAdapter::requested_enterprise_identity(agent_ref, enterprise_id, team_id, persona_handle, requested_at)`
for Grid workspaces. Do not create a workspace-only key for a Grid install; Slack Events API payloads
and outbound metadata include the enterprise id when Slack supplies it, and CID-6 routing resolves by
exact `channel + address_or_handle` equality.

This makes two agents in one workspace distinguishable while still sharing the one app install.

## Outbound Attribution

Build outbound Slack payloads with `SlackSharedPresenceAdapter::persona_outbound()`. The payload targets `chat.postMessage` and stamps the visible persona fields:

- `username` from `SlackPersonaAttribution::display_name`
- either `icon_url` or `icon_emoji`, when configured

The returned `SlackPersonaOutbound` also carries sidecar identity stamps: `workspace_ref`,
`identity_key`, and `persona_handle`. These are available to the host for receipts, idempotency, and
audit even when they are not embedded into the Slack Web API body.

Slack accepts message metadata only on app-level token paths. If the host is using a supported
app-level token/path and wants Slack-native message metadata, call
`SlackSharedPresenceAdapter::persona_outbound_with_metadata()`. Bot-token callers should use
`persona_outbound()` and keep the sidecar stamps outside Slack's request body.

Hosts still execute the Web API call and own retries/rate limits. The adapter only produces the payload shape and identity stamps.

## Inbound Routing

Hosts resolve each Events API payload to a persona handle before calling `parse_inbound()`. The adapter then emits CID-6 `InboundSurfaceEventInput` with:

- `workspace_ref = slack:workspace:<TEAM_ID>` or the Enterprise Grid form
- `receiving_address_or_handle` equal to the persona ChannelIdentity key
- `counterparty` stamped as `slack:workspace:<TEAM_ID>:user:<USER_ID>` or the Enterprise Grid form
- `foreign_inbound = true`

`Vault::route_inbound_surface_event()` resolves the ChannelIdentity, stamps the receiving identity and agent, and returns the normal CID-6 route receipt.

## Dev-Workspace Smoke Runbook

The always-on smoke test `cid8_slack_shared_presence_routes_two_agents_in_one_workspace`
validates the adapter locally with deterministic test ids. The ignored smoke seam
`cid8_slack_dev_workspace_env_smoke_seam` lets a host validate the same two-agent flow against
real dev-workspace identifiers without storing or printing Slack tokens.

Use a disposable Slack development workspace and two Oneiron personas. The host-owned Slack app
token is needed only for the real Slack install and Web API calls; keep it in the host secret store
and do not put it in the vault or shell history.

1. Create the app manifest payload with `SlackSharedPresenceAdapter::apps_manifest_create_payload()`.
2. Call Slack `apps.manifest.create` with the host-side app token, then install the app into the dev workspace.
3. Record the workspace/team id, channel id, two Slack sender user ids, and optional Enterprise Grid id.
4. Export only non-secret identifiers for the local smoke seam:

```sh
export ONEIRON_SLACK_SMOKE_WORKSPACE_ID=T123ABC
export ONEIRON_SLACK_SMOKE_CHANNEL_ID=C123ABC
export ONEIRON_SLACK_SMOKE_USER_A_ID=U123ABC
export ONEIRON_SLACK_SMOKE_USER_B_ID=U456DEF
export ONEIRON_SLACK_SMOKE_PERSONA_A=eiri
export ONEIRON_SLACK_SMOKE_PERSONA_B=herald
# Enterprise Grid only:
export ONEIRON_SLACK_SMOKE_ENTERPRISE_ID=E123ABC
```

5. Run the env-gated smoke seam:

```sh
rtk proxy cargo test -p oneiron --features sync cid8_slack_dev_workspace_env_smoke_seam -- --ignored
```

The seam creates two agent-bound Slack ChannelIdentity rows, routes two inbound Events API-shaped
payloads, and builds two outbound `chat.postMessage` payloads. It verifies:

- both personas route to distinct active identities in the same workspace
- inbound receipts and SurfaceEvents carry the expected `workspace_ref`
- Enterprise Grid identities include `slack:enterprise:<ENTERPRISE_ID>` consistently when configured
- outbound payloads carry persona-specific `username`, sidecar `identity_key`, and optional metadata stamps

For a live end-to-end workspace smoke, perform one additional host-side check after the seam passes:
send one message per persona using the generated outbound body, trigger one app mention or DM event
per persona mapping, and compare the observed workspace/persona ids with the seam inputs. Do not
log OAuth access tokens or Web API bearer headers.
