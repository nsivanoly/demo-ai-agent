# Services MCP Server (demo 3)

Tools for the Trusted Agents demo: public-services applications, fees and refunds,
with a vault for sensitive values. Runs on a managed MCP host (mcphosting) over
stdio, behind the Agent Manager MCP gateway.

## What it does and doesn't do

| This server does | The gateway does |
|---|---|
| The tools, including confidential execution in the vault | **All authorization**: every tool call is checked against the scopes in the caller's token |
| Per-call input policy: prompt injection, raw card or ID numbers, refund limits | Authentication of the caller |
| Signed, short-lived refund approvals (stateless human-in-the-loop) | |

It is **stateless**: the host starts a fresh process per request, so nothing is
remembered between calls. The audit record and risk state live in the demo's
control service. It **never knows who called**: the gateway strips the caller's
token, and under stdio no HTTP headers arrive. Each tool takes an optional `ctx`
argument that the calling agent fills in; it's echoed back as *asserted* context
and never used for a decision.

## Tools

| Tool | Scope (proxy handle `svc`) | Notes |
|---|---|---|
| `get_profile` | `svc:profile-read` | Sensitive values returned as vault references and masked displays only |
| `get_application_status` | `svc:application-read` | |
| `submit_application` | `svc:application-submit` | |
| `pay_fee` | `svc:fees-pay` | Takes a vault reference; returns a masked receipt |
| `request_refund` | `svc:refund-request` | Above `HITL_THRESHOLD` returns `HITL_REQUIRED` until given a valid `approval_ref` |
| `approve_refund` | `svc:refund-approve` | Supervisor only (enforced by the gateway); returns a signed `approval_ref` |
| `describe_payment_reference` | `svc:profile-read` | Masked |
| `whoami` | `svc:profile-read` | Shows the server has no verified identity |

## Deploying to mcphosting

The deployable unit is the **root of the `demo3-mcp` branch** of
`github.com/nsivanoly/demo-ai-agent`:

```
server.py           entrypoint; defines the module-level `mcp` object and runs it over stdio
policy.py           guardrails, vault, signed approvals
requirements.txt    fastmcp
```

1. In mcphosting, create a **new project** and connect it to the GitHub repo
   `nsivanoly/demo-ai-agent`, branch **`demo3-mcp`**. After that, every push
   to the branch builds and deploys.
2. Set the environment variable **`APPROVAL_SIGNING_KEY`** to a long random
   value. Without it, approvals are signed with a built-in demo key, and every
   approval says so.
3. Put the project's MCP URL in `setup/.env` as **`DEMO3_MCP_URL`**.

A build log saying *"Detected python project using stdio transport"* followed by
a passing *"MCP smoke test: python3 server.py"* means it worked.

## Testing locally

```
docker run --rm -v "$PWD:/app" -w /app python:3.11-slim \
  sh -c "pip install -q -r requirements.txt && python test_local.py && sh smoke_stdio.sh"
```
