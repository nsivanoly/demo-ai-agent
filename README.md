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

Platform-hosted agent, buildpack `python` 3.11, run command `python main.py`,
port 8000. `setup/demo.sh 2` does this automatically when `DEMO2_REPO_URL` is
set — this branch is the repo root, so the app path is `/`.
