# Payments Agent

The confidential-tier specialist for the WSO2 Agent Manager identity & trust
demo. Deployed as a **platform-hosted** agent, so it runs inside AMP with a real
AgentID.

```
main.py         FastAPI app  (POST /settle, GET /whoami, GET /health)
agentid.py      AgentID client-credentials helper
```

## Identity

Same as the concierge agent: AMP injects `AMP_AGENTID_CLIENT_ID`,
`AMP_AGENTID_CLIENT_SECRET`, `AMP_AGENTID_TOKEN_ENDPOINT` and
`AMP_AGENTID_SCOPES`, and `agentid.py` exchanges them for a token via the
`client_credentials` grant with RFC 8707 `resource` targeting.

This agent is the one that holds the **confidential-tier scope**. It is reached
only through a delegated credential from the concierge agent, and it never sees
a card number: it passes an opaque vault reference (`tok_...`) to the tool and
the vault de-tokenises internally, returning a masked receipt.

## How it reaches the MCP server

AMP attaches the MCP proxy to this agent and injects the gateway URL as
`<config-name>_MCP_CONFIG_URL`. `mcp_url()` prefers that, so the moment the
proxy reconciles onto the gateway the traffic flows through AMP with no code
change. On the current build the gateway returns 404 for MCP proxies, so it
falls back to `MCP_URL` — the enforcement point directly.

Either way the authorization is identical: the agent presents its real AgentID
token and the enforcement point checks the scopes AMP put in it.

## Endpoints

```
POST /settle   act under a delegated credential, on a vault reference only
GET  /whoami   the live AgentID token claims  <- useful during a demo
GET  /health
```

## Run locally

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # fill in the AgentID values from the Console
python main.py           # serves on :8000
```

## Deploy on WSO2 Agent Manager

Platform-hosted agent, **subtype `custom-api`**, buildpack `python` 3.11, run
command `python main.py`, port 8000, base path `/`, OpenAPI spec
`/openapi.yaml`.

`custom-api` is the honest subtype here — this agent exposes a task API, not a
chat endpoint. AMP then requires the interface to be described, which is what
`openapi.yaml` is for. It is generated from the FastAPI app, so regenerate it
after changing any route:

```bash
PYTHONPATH=. python -c "
import main, yaml
yaml.safe_dump(main.app.openapi(), open('openapi.yaml','w'), sort_keys=False)"
```

> The app binds **8000 explicitly**, not `$PORT`. The Google buildpack sets
> `PORT=8080` in the image, but AMP's readiness probe is a TCP check on the
> port declared in `inputInterface` (8000) — binding `$PORT` makes the probe
> fail and the pod is killed with SIGTERM. `setup/demo.sh 2` does this automatically when `DEMO2_REPO_URL` is
set — this branch is the repo root, so the app path is `/`.
