# Concierge Agent

The user-facing orchestrator for the WSO2 Agent Manager identity & trust demo.
Deployed as a **platform-hosted** agent, so it runs inside AMP with a real
AgentID.

```
main.py         FastAPI app  (POST /task, POST /spawn, GET /whoami, GET /health)
agentid.py      AgentID client-credentials helper
```

## Identity

The agent holds no credential of its own. AMP injects:

| Variable | |
|---|---|
| `AMP_AGENTID_CLIENT_ID` | OAuth client id for this environment |
| `AMP_AGENTID_CLIENT_SECRET` | client secret, via a Kubernetes secret reference |
| `AMP_AGENTID_TOKEN_ENDPOINT` | the environment ThunderID's `/oauth2/token` |
| `AMP_AGENTID_SCOPES` | the scopes to request |

`agentid.py` exchanges them for an access token using the `client_credentials`
grant, with RFC 8707 `resource` targeting so the token is bound to one resource,
cached per resource and refreshed at 75% of its lifetime.

**AMP filters the scopes in that token against the roles assigned to this
agent.** Remove a role in the Console and the scope is gone from the next token.

This agent deliberately holds only low-sensitivity scopes. Anything higher is
delegated to the payments agent.

## Endpoints

```
POST /task     run a task; delegates what it is not entitled to do
POST /spawn    ask the broker for a short-lived sub-agent identity
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
