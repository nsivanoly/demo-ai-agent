# Demo 2 — Concierge Agent

The user-facing orchestrator for the WSO2 Agent Manager identity and trust
demo. Runs as a **platform-hosted** agent: Agent Manager builds this branch,
runs it in the cluster, and injects its AgentID credentials.

## The chain it drives

```
user token (OIDC)            verified against the issuer's live JWKS
  → AgentID token            client_credentials, scopes filtered by AMP roles
  → AMP gateway → MCP        work this agent is entitled to do itself
  → OBO assertion            minted for the payments agent, narrowed scope
  → payments agent           which mints its OWN AgentID token
  → AMP gateway → MCP        the confidential call
```

`POST /task` returns one record per hop: the credential used, the decision, who
made it, and the token content. That response *is* the audit trail.

## What it deliberately cannot do

This agent holds read scopes only. Ask it to charge a card with its own token
(`{"skip_delegation": true}`) and the **gateway** returns 403 before the MCP
server is reached. Delegation here is forced by the authorization model, not
staged for the demo.

## Endpoints

| | |
|---|---|
| `POST /task` | Run one transaction on behalf of the calling user. Send the user's OIDC token as `Authorization: Bearer`. |
| `POST /spawn` | Issue a short-lived child identity with a subset of this agent's scopes. Asking for more than the parent holds is refused at issue time. |
| `POST /child-call` | Act under a previously issued child identity. |
| `GET /whoami` | This agent's AMP identity, granted scopes and gateway endpoint. |
| `GET /health` | Liveness. AMP's readiness probe is a TCP check on port 8000. |

## Configuration

AMP injects these; never set them by hand:

```
AMP_AGENTID_CLIENT_ID  AMP_AGENTID_CLIENT_SECRET
AMP_AGENTID_TOKEN_ENDPOINT  AMP_AGENTID_SCOPES
<CONFIG>_MCP_CONFIG_URL      the gateway URL for the bound MCP proxy
```

The demo setup writes these after roles are assigned:

```
AGENT_SCOPES        what to request — AMP_AGENTID_SCOPES is computed at agent
                    creation, before any role exists, so it arrives empty
MCP_GATEWAY_URL     fallback for the injected URL
OBO_SIGNING_KEY     shared with the payments agent, rotated per setup run
USER_TOKEN_ISSUER   whose JWKS to verify the user's token against
PAYMENTS_AGENT_URL  where the payments agent answers
```

## Notes that cost time to learn

* **Bind port 8000, not `$PORT`.** The buildpack sets `PORT=8080`, but AMP's
  readiness probe is a TCP check on the port declared in `inputInterface`. Bind
  `$PORT` and the pod is SIGTERMed with nothing in the log.
* **The RFC 8707 `resource` must be the gateway URL.** The identity provider
  only accepts a resource it has registered; anything else fails with
  `invalid_target`.
* **There is no direct-to-MCP fallback.** The gateway is the policy enforcement
  point. A fallback around it would make the demo prove something weaker than
  it claims, so a gateway that is not serving the proxy fails the call loudly.
