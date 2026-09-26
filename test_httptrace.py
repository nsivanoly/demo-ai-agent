"""Local check: calls are recorded (including from LangGraph nodes) and secrets are masked."""
import json
import httptrace
import httpx
from langgraph.graph import END, StateGraph
from typing import TypedDict

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzY29wZSI6InN2YzpmZWVzLXBheSJ9.c2lnbmF0dXJlLXZhbHVlLWhlcmU"
echo = httpx.MockTransport(lambda r: httpx.Response(200, json={"access_token": JWT, "token_type": "Bearer", "note": f"got {JWT}"}))
client = httpx.Client(transport=echo)

calls = httptrace.start("demo3-concierge")
client.post("http://idp/oauth2/token", auth=("client-id", "super-secret"),
            data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": JWT, "actor_token": JWT, "scope": "svc:fees-pay"})
client.post("http://gw/mcp", headers={"Authorization": f"Bearer {JWT}", "api-key": "k-123456"}, json={"method": "tools/call", "ctx": JWT})

class S(TypedDict):
    n: int
def node(s):
    client.get("http://llm/v1/models")
    return {"n": 1}
g = StateGraph(S); g.add_node("a", node); g.set_entry_point("a"); g.add_edge("a", END)
g.compile().invoke({"n": 0})

blob = json.dumps(calls)
print("calls recorded:", len(calls), [c["url"] for c in calls])
print("raw JWT anywhere in the record:", JWT in blob, "| client secret anywhere:", "super-secret" in blob, "| api key:", "k-123456" in blob)
print("exchange form as recorded:", calls[0]["request_body"])
print("auth header as recorded:", [h for h in calls[1]["request_headers"] if h[0].lower() == "authorization"])
print("token response as recorded:", calls[0]["response_body"])
