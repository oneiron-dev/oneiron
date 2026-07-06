# Slack Channel Identity Adapter

ONE-1512 implements Slack as an OF-347 `shared_presence` channel:

- one Oneiron Slack app is minted from a manifest with `apps.manifest.create`
- that one app can be installed into many Slack workspaces
- each Oneiron agent is represented as a named persona inside the app
- inbound Events API payloads are normalized through CID-6 with both the workspace stamp and the resolved ChannelIdentity

## Manifest Flow

Hosts build the manifest payload with `SlackSharedPresenceAdapter::apps_manifest_create_payload()`.
The returned JSON is the request body for Slack's `apps.manifest.create` method:

```json
{
  "manifest": {
    "display_information": { "name": "Oneiron" },
    "features": {
      "bot_user": {
        "display_name": "Oneiron",
        "always_online": false
      }
    },
    "oauth_config": {
      "redirect_urls": ["https://example.com/slack/oauth/callback"],
      "scopes": {
        "bot": [
          "app_mentions:read",
          "channels:history",
          "chat:write",
          "chat:write.customize",
          "commands",
          "im:history",
          "im:write"
        ]
      }
    },
    "settings": {
      "event_subscriptions": {
        "request_url": "https://example.com/slack/events",
        "bot_events": ["app_mention", "message.im"]
      },
      "interactivity": {
        "is_enabled": true,
        "request_url": "https://example.com/slack/events"
      },
      "org_deploy_enabled": false,
      "socket_mode_enabled": false,
      "token_rotation_enabled": true
    }
  }
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

Enterprise Grid workspaces use:

```text
slack:enterprise:<ENTERPRISE_ID>:workspace:<TEAM_ID>:persona:<persona_handle>
```

This makes two agents in one workspace distinguishable while still sharing the one app install.

## Outbound Attribution

Build outbound Slack payloads with `SlackSharedPresenceAdapter::persona_outbound()`. The payload targets `chat.postMessage` and stamps:

- `username` from `SlackPersonaAttribution::display_name`
- either `icon_url` or `icon_emoji`, when configured
- Slack message metadata with `workspace_ref`, `identity_key`, and `persona_handle`

Hosts still execute the Web API call and own retries/rate limits. The adapter only produces the payload shape and identity stamps.

## Inbound Routing

Hosts resolve each Events API payload to a persona handle before calling `parse_inbound()`. The adapter then emits CID-6 `InboundSurfaceEventInput` with:

- `workspace_ref = slack:workspace:<TEAM_ID>` or the Enterprise Grid form
- `receiving_address_or_handle` equal to the persona ChannelIdentity key
- `counterparty` stamped as `slack:workspace:<TEAM_ID>:user:<USER_ID>`
- `foreign_inbound = true`

`Vault::route_inbound_surface_event()` resolves the ChannelIdentity, stamps the receiving identity and agent, and returns the normal CID-6 route receipt.
