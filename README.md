# Demo 2 — Payments Agent

The confidential-tier specialist for the WSO2 Agent Manager identity and trust
demo. Runs as a **platform-hosted** agent with its own AgentID and the only
role that carries the confidential scope.

## The part worth pointing at

The on-behalf-of assertion the concierge sends is **not** what goes to the
gateway. This agent:

1. verifies the assertion — signature, lifetime, audience, and that the
   delegating agent is one it trusts;
2. mints its **own** AgentID token from Agent Manager;
3. presents that token to the gateway.

So the scopes the gateway authorizes come from *this agent's* AMP roles, never
from anything the caller asserted. A forged or widened assertion gets this
agent to act, at most, within its own grant — and a tampered one does not
verify at all.

It never sees a card number either: it passes an opaque vault reference and the
MCP server de-tokenises internally, returning a masked receipt.

## Endpoints

| | |
|---|---|
| `POST /settle` | Settle a payment. Requires an OBO assertion as `Authorization: Bearer`. |
| `GET /whoami` | This agent's AMP identity, granted scopes and gateway endpoint. |
| `GET /health` | Liveness. AMP's readiness probe is a TCP check on port 8000. |

## Configuration

AMP injects the AgentID credentials and `<CONFIG>_MCP_CONFIG_URL`. The demo
setup writes `AGENT_SCOPES`, `MCP_GATEWAY_URL`, `OBO_SIGNING_KEY` and
`CONFIDENTIAL_TOOL` after roles are assigned.

`TRUSTED_DELEGATORS` (default `demo2-concierge-agent`) is the list of agents
whose assertions this one will accept.

## Notes that cost time to learn

* **Bind port 8000, not `$PORT`** — the buildpack sets `PORT=8080` but AMP's
  readiness probe checks the `inputInterface` port.
* **The RFC 8707 `resource` must be the gateway URL**, or the token endpoint
  answers `invalid_target`.
