"""Local check of the consent interrupt/resume path with a scripted model and stubbed tools."""
import base64, json
import main
from langchain_core.messages import AIMessage
from langgraph.types import Command

def tok(scopes):   # an unsigned token-shaped string: only its claims are read locally
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg':'none'})}.{b({'sub':'u1','username':'alex','scope':' '.join(scopes)})}.sig"

turn = {"n": 0}
def fake_agent(state, config):
    turn["n"] += 1
    if turn["n"] == 1:
        return {"messages": [AIMessage(content="", tool_calls=[{"name": "pay_fee", "args": {"application_id": "APP-5001"}, "id": "c1"}])]}
    return {"messages": [AIMessage(content="Your fee is paid.")]}
ran = []
main.run_tool = lambda name, args, c: ran.append(name) or {"status": "paid", "receipt": "visa ****9931"}
main.agent_node.__code__ = fake_agent.__code__
main.agent_node.__globals__.update(fake_agent.__globals__)

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
g = StateGraph(main.S); g.add_node("agent", fake_agent); g.add_node("tools", main.tools_node)
g.set_entry_point("agent"); g.add_conditional_edges("agent", main._next, {"tools": "tools", END: END}); g.add_edge("tools", "agent")
main.GRAPH = g.compile(checkpointer=MemorySaver())

tid = "t1"
main._context(tid, tok(["svc:profile-read", "svc:application-read"]), "txn-test")
r = main._reply(tid, main.GRAPH.invoke({"messages": [main.HumanMessage("pay my fee")]}, {"configurable": {"thread_id": tid}}))
print("1. no fees-pay scope ->", r["status"], r.get("scopes"), "| tools run so far:", ran)
main._context(tid, tok(["svc:profile-read", "svc:application-read", "svc:fees-pay"]), "")
r = main._reply(tid, main.GRAPH.invoke(Command(resume={"approved": True}), {"configurable": {"thread_id": tid}}))
print("2. after step-up consent ->", r["status"], repr(r.get("answer")), "| tools run:", ran)
turn["n"] = 0; ran.clear(); tid = "t2"
main._context(tid, tok(["svc:profile-read"]), "txn-test2")
main.GRAPH.invoke({"messages": [main.HumanMessage("pay")]}, {"configurable": {"thread_id": tid}})
r = main._reply(tid, main.GRAPH.invoke(Command(resume={"approved": False}), {"configurable": {"thread_id": tid}}))
print("3. user denies ->", r["status"], repr(r.get("answer")), "| tools run:", ran)
