"""The whole developer-facing API in one file.

    python examples/basic/run.py
"""

from pathlib import Path

from capgate import ExecutionRefused, Harness, load_contract


def web_search(arguments):
    # A real tool would call a search API here, using credentials only this process holds.
    return {"results": [f"result for {arguments['query']!r}"]}


contract = load_contract(Path(__file__).with_name("contract.yaml"))
harness = Harness(contract, tools={"web.search": web_search})

for action, arguments in [
    ("web.search", {"query": "capability-based security"}),
    ("database.write", {"table": "users", "row": {"role": "admin"}}),
]:
    result = harness.authorize(agent="researcher", action=action, arguments=arguments)
    print(f"{action:<16} {result.decision.decision.value.upper():<9} {result.reason_code.value}")
    if result.allowed:
        print("                 ->", harness.execute(result).output)
    else:
        try:
            harness.execute(result)
        except ExecutionRefused as refused:
            print(f"                 -> executor refused: {refused.reason}")

print(f"\n{len(harness.audit)} audit records; chain intact: {harness.audit.verify()}")
