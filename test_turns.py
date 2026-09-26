"""Local check: subject lookup without a username claim, the history window, per-turn records."""
import base64, json
import identity, main
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage


def tok(claims):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return b({"alg": "none"}) + "." + b(claims) + ".x"


print("citizen, no username claim   ->", identity.citizen(tok({"sub": "sub-alex"})))
print("citizen, unknown subject     ->", repr(identity.citizen(tok({"sub": "other", "username": "blake"}))))
msgs = []
for t in range(6):
    msgs += [HumanMessage(f"q{t}"), AIMessage(content="", tool_calls=[{"name": "get_application", "args": {}, "id": f"c{t}"}]),
             ToolMessage(content="{}", tool_call_id=f"c{t}"), AIMessage(content=f"a{t}")]
w = main._window(msgs)
print(f"history window: {len(msgs)} messages -> {len(w)}; first is a user message: {isinstance(w[0], HumanMessage)} ({w[0].content})")
t1 = main._context("tid", tok({"sub": "sub-alex"}), "txn-1")["trail"].txn
t2 = main._context("tid", tok({"sub": "sub-alex"}), "txn-2")["trail"].txn
t3 = main._context("tid", tok({"sub": "sub-alex"}), "", new_turn=False)["trail"].txn
print("per-turn transaction:", t1, "->", t2, "| resume keeps", t3)
